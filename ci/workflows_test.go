package ci

import (
	_ "embed"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const contractJob = `
runs-on: ubuntu-latest
timeout-minutes: 5
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
    with:
      persist-credentials: false
  - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff
    with:
      go-version: '1.26.x'
  - run: go test -count=1 ./ci
`

// Скан trivy блокирует уязвимые зависимости, ошибки конфигурации и секреты; принятые находки
// перечислены в .trivyignore.yaml.
const securityJob = `
runs-on: ubuntu-latest
timeout-minutes: 15
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
    with:
      persist-credentials: false
  - name: Scan dependencies, configuration and secrets
    run: |
      set -euo pipefail
      # trivy читает переменные TRIVY_* как флаги: охват проверки задаёт только этот шаг.
      unset "${!TRIVY_@}"
      version=0.74.0
      sum=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
      dir="$RUNNER_TEMP/trivy"
      mkdir -p "$dir"
      curl -fsSL --retry 3 --retry-all-errors -o "$dir/trivy.tgz" \
        "https://github.com/aquasecurity/trivy/releases/download/v$version/trivy_${version}_Linux-64bit.tar.gz"
      echo "$sum  $dir/trivy.tgz" | sha256sum -c -
      tar -xzf "$dir/trivy.tgz" -C "$dir" trivy
      # Only the exact tracked test key may use the private-key exception.
      if [ "$(git hash-object internal/testdata/priv.key)" != 56b8d894dc12c146ff16e176a942b7dc44aa4562 ]; then
        echo "accepted test key differs from its reviewed fixture" >&2
        exit 1
      fi
      accepted=(--ignorefile /dev/null)
      [ -f .trivyignore.yaml ] && accepted=(--ignorefile .trivyignore.yaml)
      # Настройки сканера задаёт шаг: trivy.yaml из проверяемого дерева их не меняет.
      scan() { "$dir/trivy" fs --config /dev/null --cache-dir "$dir/cache" --exit-code 1 --no-progress "$@" .; }
      scan --scanners vuln,misconfig --severity UNKNOWN,HIGH,CRITICAL --include-dev-deps "${accepted[@]}"
      # Исправление вышло — принятая раньше уязвимость снова блокирует.
      scan --scanners vuln --severity UNKNOWN,HIGH,CRITICAL --include-dev-deps --ignore-unfixed --ignorefile /dev/null
      # Секрет в тестах, примерах и документации — такая же утечка: встроенные исключения trivy для них сняты.
      printf 'disable-allow-rules:\n  - tests\n  - examples\n  - markdown\n' > "$dir/secret.yaml"
      scan --scanners secret --secret-config "$dir/secret.yaml" "${accepted[@]}"
      # Prove that the secret scanner actually recognizes keys in tests and Markdown.
      probe="$dir/secret-probe"
      mkdir -p "$probe/tests" "$probe/docs"
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$probe/docs/probe.md" 2>/dev/null
      cp "$probe/docs/probe.md" "$probe/tests/probe_test.go"
      if "$dir/trivy" fs --config /dev/null --cache-dir "$dir/cache" --exit-code 1 --no-progress --scanners secret --secret-config "$dir/secret.yaml" --ignorefile /dev/null --format json --output "$dir/probe-results.json" "$probe"; then
        echo "synthetic private keys were not rejected" >&2
        exit 1
      fi
      python3 - "$dir/probe-results.json" <<'PY'
      import json
      import sys
      with open(sys.argv[1], encoding="utf-8") as stream:
          report = json.load(stream)
      found = {result.get("Target", "") for result in report.get("Results", [])
               if any(s.get("RuleID") == "private-key" for s in result.get("Secrets") or [])}
      for name in ("docs/probe.md", "tests/probe_test.go"):
          if not any(name in target for target in found):
              raise SystemExit(f"missing private-key detection in {name}")
      PY
`

// Принятие GO-2026-5932 в .trivyignore.yaml держится, пока openpgp нет в графе зависимостей
// ни одной проверяемой платформы.
const openpgpJob = `
runs-on: ubuntu-latest
timeout-minutes: 10
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
    with:
      persist-credentials: false
  - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff
    with:
      go-version: '1.26.x'
  # Платформы со своим кодом (linux, darwin, freebsd, windows, прочие — на примере openbsd)
  # и 32-битная сборка из CI, с cgo и без.
  - name: Проверить отсутствие golang.org/x/crypto/openpgp
    run: |
      set -euo pipefail
      dependencies="$(mktemp)"
      trap 'rm -f "$dependencies"' EXIT
      for target in linux-amd64 linux-386 linux-arm64 darwin-amd64 darwin-arm64 freebsd-amd64 windows-amd64 windows-arm64 openbsd-amd64; do
        for cgo in 0 1; do
          GOOS="${target%-*}" GOARCH="${target#*-}" CGO_ENABLED="$cgo" go list -deps -test ./... >> "$dependencies"
        done
      done
      awk '/^golang\.org\/x\/crypto\/openpgp(\/|$)/ { print; found = 1 } END { exit found }' "$dependencies"
`

const gateJob = `
name: CI
needs: [contract, build, ginkgo, integration, security, openpgp]
if: ${{ always() }}
runs-on: ubuntu-latest
timeout-minutes: 5
steps:
  - name: Require every native job
    shell: bash
    env:
      CONTRACT: ${{ needs.contract.result }}
      BUILD: ${{ needs.build.result }}
      GINKGO: ${{ needs.ginkgo.result }}
      INTEGRATION: ${{ needs.integration.result }}
      SECURITY: ${{ needs.security.result }}
      OPENPGP: ${{ needs.openpgp.result }}
    run: |
      test "$CONTRACT" = success
      test "$BUILD" = success
      test "$GINKGO" = success
      test "$INTEGRATION" = success
      test "$SECURITY" = success
      test "$OPENPGP" = success
`

func parse(raw []byte) (map[string]any, error) {
	d := yaml.NewDecoder(strings.NewReader(string(raw)))
	var node yaml.Node
	if err := d.Decode(&node); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	var inspect func(*yaml.Node) error
	inspect = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" || (n.Tag != "" && !strings.HasPrefix(n.Tag, "!!")) {
			return fmt.Errorf("YAML anchors, aliases, merges and custom tags are not supported")
		}
		for _, child := range n.Content {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(&node); err != nil {
		return nil, err
	}
	var value map[string]any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("expected a YAML mapping")
	}
	return value, nil
}

//go:embed testdata/native-jobs.yml
var nativeJobsYAML []byte

//go:embed testdata/integration-matrix-jobs.yml
var integrationMatrixJobsYAML []byte

func validate(files map[string][]byte) error {
	if len(files) != 3 {
		return fmt.Errorf("expected exactly the three native workflows")
	}
	nativeJobs, err := parse(nativeJobsYAML)
	if err != nil {
		return fmt.Errorf("invalid native job fixture: %w", err)
	}
	if len(nativeJobs) != 3 {
		return fmt.Errorf("expected exactly three native job fixtures")
	}
	for _, file := range []string{"go_build.yml", "ginkgo_test.yml", "integration.yml"} {
		workflow, err := parse(files[file])
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		jobs, ok := workflow["jobs"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s: missing jobs", file)
		}
		delete(workflow, "jobs")
		metadata := map[string]any{"permissions": map[string]any{"contents": "read"}}
		expectedJobs, ok := nativeJobs[file].(map[string]any)
		if !ok || len(expectedJobs) != 1 {
			return fmt.Errorf("%s: expected exactly one native job fixture", file)
		}
		nativeName := "build"
		if file == "integration.yml" {
			nativeName = "integration"
		}
		if _, ok := expectedJobs[nativeName].(map[string]any); !ok {
			return fmt.Errorf("%s: missing native %s fixture", file, nativeName)
		}
		switch file {
		case "go_build.yml":
			metadata["name"] = "Go Build"
			metadata["on"] = map[string]any{"pull_request": nil, "merge_group": nil, "push": map[string]any{"branches": []any{"main"}}}
			metadata["concurrency"] = map[string]any{
				"group":              "${{ github.workflow }}-${{ github.repository }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}",
				"cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
			}
			contract, err := parse([]byte(contractJob))
			if err != nil {
				return fmt.Errorf("invalid contract job fixture: %w", err)
			}
			security, err := parse([]byte(securityJob))
			if err != nil {
				return fmt.Errorf("invalid security job fixture: %w", err)
			}
			openpgp, err := parse([]byte(openpgpJob))
			if err != nil {
				return fmt.Errorf("invalid openpgp job fixture: %w", err)
			}
			gate, err := parse([]byte(gateJob))
			if err != nil {
				return fmt.Errorf("invalid gate job fixture: %w", err)
			}
			expectedJobs["contract"] = contract
			expectedJobs["security"] = security
			expectedJobs["openpgp"] = openpgp
			expectedJobs["gate"] = gate
			expectedJobs["ginkgo"] = map[string]any{"uses": "./.github/workflows/ginkgo_test.yml"}
			expectedJobs["integration"] = map[string]any{"uses": "./.github/workflows/integration.yml"}
		case "ginkgo_test.yml":
			metadata["name"] = "Ginkgo Unit Tests"
			metadata["on"] = map[string]any{"workflow_call": nil}
		case "integration.yml":
			metadata["name"] = "Integration"
			metadata["on"] = map[string]any{"workflow_call": nil}

			integrationJobs, err := parse(integrationMatrixJobsYAML)
			if err != nil {
				return fmt.Errorf("invalid integration matrix job fixture: %w", err)
			}
			if len(integrationJobs) != 4 {
				return fmt.Errorf("expected exactly four integration matrix job fixtures, got %d", len(integrationJobs))
			}
			expectedJobs = integrationJobs
			if err := validateIntegrationUnion(jobs); err != nil {
				return fmt.Errorf("integration matrix union: %w", err)
			}
		}
		if !reflect.DeepEqual(workflow, metadata) {
			return fmt.Errorf("%s: triggers, permissions or concurrency changed", file)
		}
		if len(jobs) != len(expectedJobs) {
			return fmt.Errorf("%s: native job inventory changed", file)
		}
		// Полный YAML-эталон сохраняет матрицы, команды, inputs и порядок шагов независимо от форматирования.
		for name, want := range expectedJobs {
			if !reflect.DeepEqual(jobs[name], want) {
				return fmt.Errorf("%s/%s: complete job contract changed", file, name)
			}
		}
	}
	return nil
}

func workflows(t *testing.T) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	entries, err := os.ReadDir("../.github/workflows")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("../.github/workflows", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = raw
	}
	return files
}

func TestNativeWorkflowContract(t *testing.T) {
	if err := validate(workflows(t)); err != nil {
		t.Fatal(err)
	}
}

func TestContractIgnoresYAMLFormatting(t *testing.T) {
	files := workflows(t)
	for name, raw := range files {
		value, err := parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		files[name], err = yaml.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
}

func gateBash() (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath("bash")
	}
	// Windows bash из PATH может быть WSL и не передавать переменные проверки в дочерний процесс.
	var candidates []string
	if git, err := exec.LookPath("git"); err == nil {
		if resolved, err := filepath.EvalSymlinks(git); err == nil {
			git = resolved
		}
		dir := filepath.Dir(git)
		for _, relative := range []string{"bash.exe", "../bin/bash.exe", "../../bin/bash.exe"} {
			candidates = append(candidates, filepath.Join(dir, relative))
		}
	}
	for _, key := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if root := os.Getenv(key); root != "" {
			if key == "LOCALAPPDATA" {
				root = filepath.Join(root, "Programs")
			}
			candidates = append(candidates, filepath.Join(root, "Git", "bin", "bash.exe"))
		}
	}
	for _, candidate := range candidates {
		if bash, err := exec.LookPath(candidate); err == nil {
			return bash, nil
		}
	}
	return "", fmt.Errorf("Git Bash is required to execute the CI gate contract")
}

func TestGateBashMissingFails(t *testing.T) {
	for _, key := range []string{"PATH", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		t.Setenv(key, t.TempDir())
	}
	if bash, err := gateBash(); err == nil {
		t.Fatalf("missing Bash must fail, got %s", bash)
	}
}

func TestGateResults(t *testing.T) {
	files := workflows(t)
	w, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	jobs := w["jobs"].(map[string]any)
	gate, ok := jobs["gate"].(map[string]any)
	if !ok {
		t.Fatal("missing native gate")
	}
	step := gate["steps"].([]any)[0].(map[string]any)
	script := step["run"].(string)
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"CONTRACT", "BUILD", "GINKGO", "INTEGRATION", "SECURITY", "OPENPGP"}
	check := func(t *testing.T, results map[string]string, wantSuccess bool) {
		t.Helper()
		cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !slices.Contains(keys, key) {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		for key, value := range results {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("bash unavailable: %v", err)
			}
		}
		if (err == nil) != wantSuccess {
			t.Fatalf("results=%v: err=%v output=%s", results, err, out)
		}
	}
	all := func() map[string]string {
		results := make(map[string]string)
		for _, key := range keys {
			results[key] = "success"
		}
		return results
	}
	t.Run("all success", func(t *testing.T) { check(t, all(), true) })
	for _, key := range keys {
		for _, result := range []string{"failure", "cancelled", "skipped", "neutral", "", "unknown", "missing"} {
			t.Run(key+"/"+result, func(t *testing.T) {
				results := all()
				if result == "missing" {
					delete(results, key)
				} else {
					results[key] = result
				}
				check(t, results, false)
			})
		}
	}
	t.Run("empty", func(t *testing.T) { check(t, map[string]string{}, false) })
}

func TestAcceptedKeyMatchesReviewedBlob(t *testing.T) {
	fixture, err := os.ReadFile("../internal/testdata/priv.key")
	if err != nil {
		t.Fatal(err)
	}
	hash := func(data []byte) string {
		h := sha1.New()
		fmt.Fprintf(h, "blob %d%c", len(data), 0)
		h.Write(data)
		return fmt.Sprintf("%x", h.Sum(nil))
	}
	const reviewedBlob = "56b8d894dc12c146ff16e176a942b7dc44aa4562"
	if got := hash(fixture); got != reviewedBlob {
		t.Fatalf("test key fixture changed: %s", got)
	}
	if got := hash(append(append([]byte(nil), fixture...), 'x')); got == reviewedBlob {
		t.Fatal("modified test fixture would pass the allowed key check")
	}
}

func TestOpenPGPRejectsForbiddenOrUnresolvedGraph(t *testing.T) {
	files := workflows(t)
	w, err := parse(files["go_build.yml"])
	if err != nil { t.Fatal(err) }
	job := w["jobs"].(map[string]any)["openpgp"].(map[string]any)
	steps := job["steps"].([]any)
	script := steps[len(steps)-1].(map[string]any)["run"].(string)
	bash, err := gateBash()
	if err != nil { t.Fatal(err) }
	const stub = `go() {
	  if [ "$GOOS-$GOARCH-$CGO_ENABLED" = "$PROBE_TARGET" ]; then
	    case "$PROBE_MODE" in
	      forbidden) echo golang.org/x/crypto/openpgp/armor; return 0 ;;
	      fail) return 17 ;;
	    esac
	  fi
	  echo fmt
	}`
	check := func(target, mode string, success bool) {
		t.Helper()
		cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", stub+"\n"+script)
		cmd.Env = append(os.Environ(), "PROBE_TARGET="+target, "PROBE_MODE="+mode)
		out, err := cmd.CombinedOutput()
		if (err == nil) != success { t.Fatalf("target=%s mode=%s: err=%v, output=%s", target, mode, err, out) }
	}
	check("", "", true)
	parts := strings.SplitN(script, "for target in ", 2)
	if len(parts) != 2 { t.Fatal("no platform matrix") }
	targets := strings.Fields(strings.SplitN(parts[1], "; do", 2)[0])
	if len(targets) < 2 { t.Fatal("missing multi-platform coverage") }
	for _, target := range targets {
		for _, cgo := range []string{"0", "1"} {
			key := target+"-"+cgo
			t.Run(key+"/forbidden", func(t *testing.T) { check(key, "forbidden", false) })
			t.Run(key+"/failed-go-list", func(t *testing.T) { check(key, "fail", false) })
		}
	}
}

func TestContractRejectsMutations(t *testing.T) {
	mutations := []struct{ name, file, before, after string }{
		{"integration gate skips failure", "integration.yml", "    if: ${{ always() }}", "    if: ${{ success() }}"},
		{"integration gate misses benchmarks", "integration.yml", "needs: [integration, ancillary, benchmarks]", "needs: [integration, ancillary]"},
		{"integration gate constant binding", "integration.yml", "SELF: ${{ needs.integration.result }}", "SELF: success"},
		{"integration gate ignores benchmarks", "integration.yml", "test \"$BENCHMARKS\" = success", "true"},
		{"integration matrix fail-fast", "integration.yml", "fail-fast: false", "fail-fast: true"},
		{"self GSO environment removed", "integration.yml", "echo \"QUIC_GO_DISABLE_GSO=true\"", "echo \"QUIC_GO_DISABLE_GSO=false\""},
		{"self ECN environment removed", "integration.yml", "echo \"QUIC_GO_DISABLE_ECN=true\"", "echo \"QUIC_GO_DISABLE_ECN=false\""},
		{"PR filter", "go_build.yml", "  pull_request:", "  pull_request:\n    paths: ['*.go']"},
		{"merge group removed", "go_build.yml", "  merge_group:\n", ""},
		{"shared non-PR concurrency", "go_build.yml", "github.run_id", "github.ref"},
		{"gate skips failures", "go_build.yml", "${{ always() }}", "${{ success() }}"},
		{"gate misses integration", "go_build.yml", "needs: [contract, build, ginkgo, integration, security, openpgp]", "needs: [contract, build, ginkgo, security, openpgp]"},
		{"gate misses security", "go_build.yml", "needs: [contract, build, ginkgo, integration, security, openpgp]", "needs: [contract, build, ginkgo, integration, openpgp]"},
		{"gate misses openpgp", "go_build.yml", "needs: [contract, build, ginkgo, integration, security, openpgp]", "needs: [contract, build, ginkgo, integration, security]"},
		{"gate unconditional success", "go_build.yml", "test \"$INTEGRATION\" = success", "true"},
		{"gate ignores security", "go_build.yml", "test \"$SECURITY\" = success", "true"},
		{"gate ignores openpgp", "go_build.yml", "test \"$OPENPGP\" = success", "true"},
		{"security scan disabled", "go_build.yml", "  security:\n", "  security:\n    if: false\n"},
		{"accepted key check removed", "go_build.yml", "          if [ \"$(git hash-object internal/testdata/priv.key)\" != 56b8d894dc12c146ff16e176a942b7dc44aa4562 ]; then\n", ""},
		{"openpgp go list errors ignored", "go_build.yml", "go list -deps -test ./... >> \"$dependencies\"", "go list -deps -test ./... >> \"$dependencies\" || true"},
		{"security scan tolerates failure", "go_build.yml", "  security:\n", "  security:\n    continue-on-error: true\n"},
		{"scanner checksum changed", "go_build.yml", "sum=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a", "sum=$(curl -fsSL \"$url.sha256\")"},
		{"accepted findings mask a released fix", "go_build.yml", "--ignore-unfixed --ignorefile /dev/null", "--ignore-unfixed \"${accepted[@]}\""},
		{"secret scan removed", "go_build.yml", "          scan --scanners secret --secret-config \"$dir/secret.yaml\" \"${accepted[@]}\"\n", ""},
		{"secret scan skips tests and docs", "go_build.yml", "--secret-config \"$dir/secret.yaml\" ", ""},
		{"scanner reads trivy.yaml from the tree", "go_build.yml", "fs --config /dev/null ", "fs "},
		{"scanner reads TRIVY_* from the environment", "go_build.yml", "          unset \"${!TRIVY_@}\"\n", ""},
		{"openpgp check without test packages", "go_build.yml", "go list -deps -test ./...", "go list -deps ./..."},
		{"openpgp check tolerates a match", "go_build.yml", "END { exit found }", "END { exit 0 }"},
		{"openpgp check misses a platform", "go_build.yml", " freebsd-amd64", ""},
		{"caller disabled", "go_build.yml", "  ginkgo:\n", "  ginkgo:\n    if: false\n"},
		{"caller tolerates failure", "go_build.yml", "  integration:\n", "  integration:\n    continue-on-error: true\n"},
		{"caller inputs", "go_build.yml", "  ginkgo:\n", "  ginkgo:\n    with:\n      skip: true\n"},
		{"unknown root job", "go_build.yml", "jobs:\n", "jobs:\n  hidden:\n    runs-on: ubuntu-latest\n    steps: [{run: 'false'}]\n"},
		{"gate wrong result binding", "go_build.yml", "INTEGRATION: ${{ needs.integration.result }}", "INTEGRATION: success"},
		{"worker bypass", "ginkgo_test.yml", "  workflow_call:", "  pull_request:"},
		{"test stub", "ginkgo_test.yml", "run: go run", "run: echo go run"},
		{"worker failure tolerated", "ginkgo_test.yml", "  build:\n", "  build:\n    continue-on-error: true\n"},
		{"worker extra job", "ginkgo_test.yml", "jobs:\n", "jobs:\n  hidden:\n    runs-on: ubuntu-latest\n    steps: [{run: 'false'}]\n"},
		{"native mac removed", "go_build.yml", ", \"macos-latest\"", ""},
		{"Go matrix reduced", "ginkgo_test.yml", "\"1.26.0\", ", ""},
		{"action changed", "go_build.yml", "actions/checkout@v4", "actions/checkout@v3"},
		{"contract checkout credentials", "go_build.yml", "persist-credentials: false", "persist-credentials: true"},
		{"contract checkout defaults", "go_build.yml", "        with:\n          persist-credentials: false\n", ""},
		{"contract checkout pin", "go_build.yml", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@v4"},
		{"contract Go setup pin", "go_build.yml", "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "actions/setup-go@v5"},
		{"action inputs changed", "go_build.yml", "go-version: ${{ matrix.go }}", "go-version: '1.26.x'"},
		{"steps reordered", "go_build.yml", "    - uses: actions/checkout@v4\n    - uses: actions/setup-go@v5", "    - uses: actions/setup-go@v5\n    - uses: actions/checkout@v4"},
		{"integration native runner", "integration.yml", "${{ format('{0}-latest', matrix.os) }}", "ubuntu-latest"},
		{"integration disabled", "integration.yml", "  integration:\n", "  integration:\n    if: false\n"},
		{"test condition changed", "integration.yml", "if: success() || failure()", "if: success()"},
		{"race disabled", "integration.yml", "race: true", "race: false"},
		{"32-bit disabled", "integration.yml", "use32bit: true", "use32bit: false"},
		{"test failure tolerated", "integration.yml", "./integrationtests/tools/...\n", "./integrationtests/tools/...\n        continue-on-error: true\n"},
		{"duplicate key", "go_build.yml", "name: \"Go Build\"", "name: \"Go Build\"\nname: ignored"},
		{"multiple documents", "go_build.yml", "name: \"Go Build\"", "name: \"Go Build\"\n---"},
		{"YAML alias", "go_build.yml", "name: \"Go Build\"", "name: &title \"Go Build\""},
		{"YAML merge", "go_build.yml", "jobs:\n", "jobs:\n  <<: {hidden: {}}\n"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			files := workflows(t)
			before := strings.ReplaceAll(string(files[mutation.file]), "\r\n", "\n")
			after := strings.Replace(before, mutation.before, mutation.after, 1)
			if before == after {
				t.Fatal("mutation did not apply")
			}
			files[mutation.file] = []byte(after)
			if err := validate(files); err == nil {
				t.Fatal("mutation survived")
			}
		})
	}
	t.Run("unknown workflow", func(t *testing.T) {
		files := workflows(t)
		files["extra.yml"] = []byte("on: pull_request")
		if validate(files) == nil {
			t.Fatal("unknown workflow accepted")
		}
	})
	t.Run("missing worker", func(t *testing.T) {
		files := workflows(t)
		delete(files, "integration.yml")
		if validate(files) == nil {
			t.Fatal("missing worker accepted")
		}
	})
}

// Полные пакеты не делятся по функциям. Независимый набор ниже фиксирует все
// исходные 18 self-вариантов, шесть вспомогательных пар и пять benchmark-запусков.
func integrationMatrixSet(jobs map[string]any, name string, fields []string) (map[string]bool, error) {
	job, ok := jobs[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: missing matrix job", name)
	}
	strategy, ok := job["strategy"].(map[string]any)
	if !ok || strategy["fail-fast"] != false {
		return nil, fmt.Errorf("%s: fail-fast must remain false", name)
	}
	matrix, ok := strategy["matrix"].(map[string]any)
	if !ok || len(matrix) != 1 {
		return nil, fmt.Errorf("%s: expected only explicit include rows", name)
	}
	rows, ok := matrix["include"].([]any)
	if !ok || len(rows) == 0 {
		return nil, fmt.Errorf("%s: missing include rows", name)
	}
	result := make(map[string]bool)
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || len(row) != len(fields) {
			return nil, fmt.Errorf("%s: incomplete or extra row fields", name)
		}
		tuple := make([]string, 0, len(fields))
		for _, field := range fields {
			switch field {
			case "race", "use32bit":
				value, ok := row[field].(bool)
				if !ok {
					return nil, fmt.Errorf("%s: %s must be boolean", name, field)
				}
				tuple = append(tuple, fmt.Sprint(value))
			case "version":
				value, ok := row[field].(int)
				if !ok {
					return nil, fmt.Errorf("%s: version must be an integer", name)
				}
				tuple = append(tuple, fmt.Sprint(value))
			default:
				value, ok := row[field].(string)
				if !ok || value == "" {
					return nil, fmt.Errorf("%s: %s must be a nonempty string", name, field)
				}
				tuple = append(tuple, value)
			}
		}
		key := strings.Join(tuple, "|")
		if result[key] {
			return nil, fmt.Errorf("%s: duplicate case %s", name, key)
		}
		result[key] = true
	}
	return result, nil
}

func integrationCaseSet(keys ...string) map[string]bool {
	result := make(map[string]bool)
	for _, key := range keys {
		result[key] = true
	}
	return result
}

func validateIntegrationUnion(jobs map[string]any) error {
	policies := []struct {
		name     string
		fields   []string
		cases    map[string]bool
		commands []string
	}{
		{
			"integration",
			[]string{"os", "go", "race", "use32bit", "mode", "version"},
			integrationCaseSet(
				"ubuntu|1.26.0|false|false|v1|1",
				"ubuntu|1.26.0|false|false|v2|2",
				"ubuntu|1.26.0|false|false|gso|1",
				"ubuntu|1.26.0|false|false|ecn|1",
				"ubuntu|1.26.x|false|false|v1|1",
				"ubuntu|1.26.x|false|false|v2|2",
				"ubuntu|1.26.x|false|false|gso|1",
				"ubuntu|1.26.x|false|false|ecn|1",
				"ubuntu|1.26.x|true|false|v1|1",
				"ubuntu|1.26.x|true|false|gso|1",
				"ubuntu|1.26.x|false|true|v1|1",
				"ubuntu|1.26.x|false|true|v2|2",
				"ubuntu|1.26.x|false|true|gso|1",
				"ubuntu|1.26.x|false|true|ecn|1",
				"windows|1.26.x|false|false|v1|1",
				"windows|1.26.x|false|false|v2|2",
				"macos|1.26.x|false|false|v1|1",
				"macos|1.26.x|false|false|v2|2",
			),
			[]string{"go test ${{ env.RACEFLAG }} -v -timeout 5m -shuffle=on ./integrationtests/self -version=${{ matrix.version }} ${{ env.QLOGFLAG }}"},
		},
		{
			"ancillary",
			[]string{"os", "go", "race", "use32bit"},
			integrationCaseSet(
				"ubuntu|1.26.0|false|false",
				"ubuntu|1.26.x|false|false",
				"ubuntu|1.26.x|true|false",
				"ubuntu|1.26.x|false|true",
				"windows|1.26.x|false|false",
				"macos|1.26.x|false|false",
			),
			[]string{"go test ${{ env.RACEFLAG }} -v -timeout 30s -shuffle=on ./integrationtests/tools/...", "go test ${{ env.RACEFLAG }} -v -timeout 30s -shuffle=on ./integrationtests/versionnegotiation ${{ env.QLOGFLAG }}"},
		},
		{
			"benchmarks",
			[]string{"os", "go", "race", "use32bit"},
			integrationCaseSet(
				"ubuntu|1.26.0|false|false",
				"ubuntu|1.26.x|false|false",
				"ubuntu|1.26.x|false|true",
				"windows|1.26.x|false|false",
				"macos|1.26.x|false|false",
			),
			[]string{"go test -v -run=^$ -timeout 5m -shuffle=on -bench=. ./integrationtests/self"},
		},
	}
	for _, policy := range policies {
		got, err := integrationMatrixSet(jobs, policy.name, policy.fields)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, policy.cases) {
			return fmt.Errorf("%s: complete invocation union changed", policy.name)
		}
		job := jobs[policy.name].(map[string]any)
		if !reflect.DeepEqual(job["env"], map[string]any{"DEBUG": false, "TIMESCALE_FACTOR": 3}) {
			return fmt.Errorf("%s: integration timing or qlog environment changed", policy.name)
		}
		steps, ok := job["steps"].([]any)
		if !ok {
			return fmt.Errorf("%s: missing steps", policy.name)
		}
		var commands []string
		for _, value := range steps {
			step, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: invalid step", policy.name)
			}
			if command, ok := step["run"].(string); ok && strings.HasPrefix(command, "go test ") {
				commands = append(commands, command)
			}
		}
		if !reflect.DeepEqual(commands, policy.commands) {
			return fmt.Errorf("%s: complete package command changed", policy.name)
		}
	}
	return nil
}

func TestIntegrationUnionRejectsMissingAndRepeatedCases(t *testing.T) {
	for _, name := range []string{"integration", "ancillary", "benchmarks"} {
		for _, mutation := range []string{"missing", "duplicate", "unknown row", "extra axis", "timing", "selector"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				workflow, err := parse(workflows(t)["integration.yml"])
				if err != nil {
					t.Fatal(err)
				}
				jobs := workflow["jobs"].(map[string]any)
				if err := validateIntegrationUnion(jobs); err != nil {
					t.Fatal(err)
				}
				job := jobs[name].(map[string]any)
				matrix := job["strategy"].(map[string]any)["matrix"].(map[string]any)
				rows := matrix["include"].([]any)
				switch mutation {
				case "missing":
					matrix["include"] = rows[1:]
				case "duplicate":
					matrix["include"] = append(rows, rows[0])
				case "unknown row":
					rows[0].(map[string]any)["go"] = "unknown"
				case "extra axis":
					matrix["skip"] = []any{false, true}
				case "timing":
					job["env"].(map[string]any)["TIMESCALE_FACTOR"] = 1
				case "selector":
					for _, value := range job["steps"].([]any) {
						step := value.(map[string]any)
						if command, ok := step["run"].(string); ok && strings.HasPrefix(command, "go test ") {
							step["run"] = command + " -short"
							break
						}
					}
				}
				if validateIntegrationUnion(jobs) == nil {
					t.Fatal("independent integration union accepted mutation")
				}
			})
		}
	}
}

func TestIntegrationGateResults(t *testing.T) {
	workflow, err := parse(workflows(t)["integration.yml"])
	if err != nil {
		t.Fatal(err)
	}
	gate := workflow["jobs"].(map[string]any)["gate"].(map[string]any)
	script := gate["steps"].([]any)[0].(map[string]any)["run"].(string)
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"SELF", "ANCILLARY", "BENCHMARKS"}
	check := func(t *testing.T, results map[string]string, wantSuccess bool) {
		t.Helper()
		cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if key != "SELF" && key != "ANCILLARY" && key != "BENCHMARKS" {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		for key, value := range results {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("bash unavailable: %v", err)
			}
		}
		if (err == nil) != wantSuccess {
			t.Fatalf("results=%v: err=%v output=%s", results, err, out)
		}
	}
	all := func() map[string]string {
		return map[string]string{"SELF": "success", "ANCILLARY": "success", "BENCHMARKS": "success"}
	}
	t.Run("all success", func(t *testing.T) { check(t, all(), true) })
	for _, key := range keys {
		for _, result := range []string{"failure", "cancelled", "skipped", "neutral", "", "unknown", "missing"} {
			t.Run(key+"/"+result, func(t *testing.T) {
				results := all()
				if result == "missing" {
					delete(results, key)
				} else {
					results[key] = result
				}
				check(t, results, false)
			})
		}
	}
	t.Run("empty", func(t *testing.T) { check(t, map[string]string{}, false) })
}
