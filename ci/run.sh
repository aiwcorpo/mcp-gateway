#!/usr/bin/env bash
# Single CI entry point (M5-5): every CI system, the container image of ci/Dockerfile and a developer's shell call this script and
# nothing else. .gitlab-ci.yml, Jenkinsfile and .github/workflows/ci.yml are thin wrappers around it. Needs bash, git, JDK 25 and
# either a filled ~/.m2 with the mcp-contracts artifacts or MCP_MAVEN_REPOSITORY_URL (+ _USER, _PASSWORD) pointing at the registry
# that holds them.
#
#   ci/run.sh                 verify (default)
#   ci/run.sh verify          hygiene checks, then unit and integration tests of both modules (mvnw clean verify)
#   ci/run.sh hygiene         only the text checks of the sources (non-ASCII quotes and spaces, tool traces)
#   ci/run.sh image           verify, then build the container image mcp-gateway:m6-<short sha> from the jar
#                             (needs a clean checkout, so that the tag names the code it holds)
#
# Any failure of a step is the exit code of the script. An unknown step, no step at all and a build that ran no test are errors.
# The integration tests start PostgreSQL and Redis with Testcontainers, so a container runtime must be reachable (a Docker socket
# mounted into the CI container, or DOCKER_HOST). CI_MVNW replaces ./mvnw (the self-test of this script uses a stand-in).
#
# No "set -e": a step called in a condition or after || would run with it switched off, so every step checks what it runs.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 1

fail() {
  echo "ci/run.sh: $*" >&2
  return 1
}

mvnw() {
  local wrapper="${CI_MVNW:-./mvnw}"
  if [[ -n "${MCP_MAVEN_REPOSITORY_URL:-}" ]]; then
    "$wrapper" -B -s .ci/settings.xml "$@"
  else
    "$wrapper" -B "$@"
  fi
}

tracked_sources() {
  git ls-files -z --cached --others --exclude-standard -- '*.java' '*.md' '*.xml' '*.yml' '*.yaml' '*.properties' '*.json' '*.sh' 'Jenkinsfile' 'Dockerfile' 'ci/Dockerfile' ':!:ci/run.sh' ':!:ci/self-test.sh'
}

# The two checks of the house style: characters that give away generated text, and phrases left by tools. One perl process reads
# every file by its literal name (<<>> and not the two-argument open of <>, which would run a name such as "x |") and prints what it
# finds; it always exits 0, so a non-zero status of xargs or perl is a failure of the check itself and never "nothing found".
step_hygiene() {
  local found
  found="$(tracked_sources | xargs -0 perl -CSD -e '
    while (<<>>) {
      print "$ARGV:$.: non-ASCII quote, space or ellipsis: $_" if /[\x{00A0}\x{200B}\x{202F}\x{FEFF}\x{2018}\x{2019}\x{201C}\x{201D}\x{2026}]/;
      print "$ARGV:$.: tool trace or placeholder: $_" if /as an ai|generated with|co-authored-by: claude|lorem ipsum|your-api-key|example\.com/i;
    } continue { close ARGV if eof }
    exit 0' --; printf 'status=%s\n' "${PIPESTATUS[1]}")"
  local status="${found##*status=}"
  found="${found%status=*}"
  if [[ "$status" != "0" ]]; then
    fail "the hygiene check itself failed (status $status)"
    return 1
  fi
  if [[ -n "$found" ]]; then
    printf '%s' "$found" >&2
    fail "hygiene findings (above)"
    return 1
  fi
}

# A build that ran no test proves nothing (a skipped module, a broken surefire setup, every test skipped), so each module must have run
# tests that were not skipped, and the gateway at least CI_GATEWAY_MIN_TESTS of them (a floor, so that a test class that quietly
# stopped being found shows).
module_executed() {
  local module="$1" tests=0 skipped=0 t k file
  while IFS= read -r file; do
    t="$(sed -n 's/.*<testsuite [^>]*[ ]tests="\([0-9]*\)".*/\1/p' "$file" | head -n 1)"
    k="$(sed -n 's/.*<testsuite [^>]*[ ]skipped="\([0-9]*\)".*/\1/p' "$file" | head -n 1)"
    tests=$((tests + ${t:-0}))
    skipped=$((skipped + ${k:-0}))
  done < <(find "$module/target/surefire-reports" -name 'TEST-*.xml' 2>/dev/null)
  echo $((tests - skipped))
}

step_verify() {
  step_hygiene || return 1
  mvnw clean verify || return 1
  local module executed floor
  for module in gateway test-server; do
    executed="$(module_executed "$module")"
    floor=1
    if [[ "$module" == "gateway" ]]; then
      floor="${CI_GATEWAY_MIN_TESTS:-600}"
    fi
    if [[ "$executed" -lt "$floor" || "$executed" -eq 0 ]]; then
      fail "$module ran $executed tests that were not skipped; at least $floor are required"
      return 1
    fi
    echo "ci/run.sh: $module: $executed tests ran"
  done
}

step_image() {
  if [[ -n "$(git status --porcelain)" ]]; then
    fail "image: the working tree has uncommitted changes; the tag would not name the code in the image"
    return 1
  fi
  step_verify || return 1
  local tag
  tag="mcp-gateway:m6-$(git rev-parse --short HEAD)" || return 1
  docker build -t "$tag" . || return 1
  echo "ci/run.sh: built $tag"
}

if [[ $# -gt 1 ]]; then
  echo "usage: ci/run.sh [verify|hygiene|image]" >&2
  exit 2
fi
step="${1-verify}"
case "$step" in
  verify|hygiene|image) ;;
  *) echo "ci/run.sh: unknown step '$step'; usage: ci/run.sh [verify|hygiene|image]" >&2; exit 2 ;;
esac
"step_$step"
exit $?
