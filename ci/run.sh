#!/usr/bin/env bash
# Single CI entry point (M5-5): every CI system, the container image of ci/Dockerfile and a developer's shell call this script and
# nothing else. .gitlab-ci.yml, Jenkinsfile and .github/workflows/ci.yml are thin wrappers around it. Needs bash, git, JDK 25 and
# either a filled ~/.m2 with the mcp-contracts artifacts or MCP_MAVEN_REPOSITORY_URL (+ _USER, _PASSWORD) pointing at the registry
# that holds them.
#
#   ci/run.sh                 verify (default)
#   ci/run.sh verify          hygiene checks, then unit and integration tests of both modules (mvnw clean verify)
#   ci/run.sh hygiene         only the text checks of the sources (non-ASCII quotes and spaces, tool traces)
#   ci/run.sh image           verify, then build the container image mcp-gateway:m5-<short sha> from the jar
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

# The two checks of the house style: characters that give away generated text, and phrases left by tools.
step_hygiene() {
  local failed=0
  if ! tracked_sources | xargs -0 perl -CSD -ne 'if (/[\x{00A0}\x{200B}\x{202F}\x{FEFF}\x{2018}\x{2019}\x{201C}\x{201D}\x{2026}]/) { print "$ARGV:$.: $_"; $bad = 1 } END { exit($bad ? 1 : 0) }'; then
    echo "ci/run.sh: non-ASCII quotes, spaces or ellipsis found (above)" >&2
    failed=1
  fi
  if tracked_sources | xargs -0 grep -niE 'as an ai|generated with|co-authored-by: claude|lorem ipsum|your-api-key|example\.com' --; then
    echo "ci/run.sh: tool traces or placeholders found (above)" >&2
    failed=1
  fi
  return "$failed"
}

# A build that ran no test proves nothing (a skipped module, a broken surefire setup), so it fails.
tests_run() {
  local total=0 count file
  while IFS= read -r file; do
    count="$(sed -n 's/.*<testsuite [^>]*[ ]tests="\([0-9]*\)".*/\1/p' "$file" | head -n 1)"
    total=$((total + ${count:-0}))
  done < <(find gateway/target/surefire-reports test-server/target/surefire-reports -name 'TEST-*.xml' 2>/dev/null)
  echo "$total"
}

step_verify() {
  step_hygiene || return 1
  mvnw clean verify || return 1
  local total
  total="$(tests_run)"
  if [[ "$total" -eq 0 ]]; then
    fail "no test ran (zero tests in the surefire reports of both modules); zero tests is a failure"
    return 1
  fi
  echo "ci/run.sh: $total tests ran"
}

step_image() {
  if [[ -n "$(git status --porcelain)" ]]; then
    fail "image: the working tree has uncommitted changes; the tag would not name the code in the image"
    return 1
  fi
  step_verify || return 1
  local tag
  tag="mcp-gateway:m5-$(git rev-parse --short HEAD)" || return 1
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
