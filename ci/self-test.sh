#!/usr/bin/env bash
# Self-test of ci/run.sh with a stand-in for mvnw: a failed build must fail the script, an unknown or empty step must be refused,
# and a build with no test report must fail. Runs without a JDK, a container runtime or a network.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ci" "$work/gateway/target/surefire-reports" "$work/test-server/target/surefire-reports"
cp "$root/ci/run.sh" "$work/ci/run.sh"
cp -R "$root/.ci" "$work/.ci"
git -C "$work" init -q
check() {
  local name="$1" expected="$2"
  shift 2
  "$@" >"$work/out" 2>&1
  local got=$?
  if [[ "$got" != "$expected" ]]; then
    echo "FAIL $name: exit $got, wanted $expected" >&2
    cat "$work/out" >&2
    exit 1
  fi
  echo "ok   $name"
}
printf '#!/usr/bin/env bash\nexit 1\n' >"$work/fake-fails"
printf '#!/usr/bin/env bash\nexit 0\n' >"$work/fake-passes"
chmod +x "$work/fake-fails" "$work/fake-passes"
check "a failed build fails the script" 1 env CI_MVNW="$work/fake-fails" "$work/ci/run.sh" verify
check "a build that ran no test fails" 1 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" verify
echo '<testsuite name="x" tests="3" failures="0"></testsuite>' >"$work/gateway/target/surefire-reports/TEST-x.xml"
check "a build with tests passes" 0 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" verify
check "an unknown step is refused" 2 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" nonsense
check "an empty step is refused" 2 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" ""
check "two steps are refused" 2 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" verify hygiene
printf 'quote \xe2\x80\x99 here\n' >"$work/bad.md"
git -C "$work" add bad.md
check "hygiene finds a typographic quote" 1 env CI_MVNW="$work/fake-passes" "$work/ci/run.sh" hygiene
printf 'ok\n' >"$work/touch-me |"
printf 'x' >"$work/ran"
git -C "$work" add "touch-me |" 2>/dev/null
check "a file name with a pipe is read, not run" 0 env CI_MVNW="$work/fake-passes" bash -c "cd '$work' && git rm -q --cached bad.md && rm bad.md && ci/run.sh hygiene"
