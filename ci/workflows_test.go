package ci

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
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
      go-version: '1.24.x'
  - run: go test -count=1 ./ci
`

const gateJob = `
name: CI
needs: [contract, build, ginkgo, integration]
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
    run: |
      test "$CONTRACT" = success
      test "$BUILD" = success
      test "$GINKGO" = success
      test "$INTEGRATION" = success
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
			gate, err := parse([]byte(gateJob))
			if err != nil {
				return fmt.Errorf("invalid gate job fixture: %w", err)
			}
			expectedJobs["contract"] = contract
			expectedJobs["gate"] = gate
			expectedJobs["ginkgo"] = map[string]any{"uses": "./.github/workflows/ginkgo_test.yml"}
			expectedJobs["integration"] = map[string]any{"uses": "./.github/workflows/integration.yml"}
		case "ginkgo_test.yml":
			metadata["name"] = "Ginkgo Unit Tests"
			metadata["on"] = map[string]any{"workflow_call": nil}
		case "integration.yml":
			metadata["name"] = "Integration"
			metadata["on"] = map[string]any{"workflow_call": nil}
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
	keys := []string{"CONTRACT", "BUILD", "GINKGO", "INTEGRATION"}
	check := func(t *testing.T, results map[string]string, wantSuccess bool) {
		t.Helper()
		cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if key != "CONTRACT" && key != "BUILD" && key != "GINKGO" && key != "INTEGRATION" {
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
		return map[string]string{"CONTRACT": "success", "BUILD": "success", "GINKGO": "success", "INTEGRATION": "success"}
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

func TestContractRejectsMutations(t *testing.T) {
	mutations := []struct{ name, file, before, after string }{
		{"PR filter", "go_build.yml", "  pull_request:", "  pull_request:\n    paths: ['*.go']"},
		{"merge group removed", "go_build.yml", "  merge_group:\n", ""},
		{"shared non-PR concurrency", "go_build.yml", "github.run_id", "github.ref"},
		{"gate skips failures", "go_build.yml", "${{ always() }}", "${{ success() }}"},
		{"gate misses integration", "go_build.yml", "needs: [contract, build, ginkgo, integration]", "needs: [contract, build, ginkgo]"},
		{"gate unconditional success", "go_build.yml", "test \"$INTEGRATION\" = success", "true"},
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
		{"Go matrix reduced", "ginkgo_test.yml", "\"1.23.x\", ", ""},
		{"action changed", "go_build.yml", "actions/checkout@v4", "actions/checkout@v3"},
		{"contract checkout credentials", "go_build.yml", "persist-credentials: false", "persist-credentials: true"},
		{"contract checkout defaults", "go_build.yml", "        with:\n          persist-credentials: false\n", ""},
		{"contract checkout pin", "go_build.yml", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@v4"},
		{"contract Go setup pin", "go_build.yml", "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "actions/setup-go@v5"},
		{"action inputs changed", "go_build.yml", "go-version: ${{ matrix.go }}", "go-version: '1.24.x'"},
		{"steps reordered", "go_build.yml", "    - uses: actions/checkout@v4\n    - uses: actions/setup-go@v5", "    - uses: actions/setup-go@v5\n    - uses: actions/checkout@v4"},
		{"integration native runner", "integration.yml", "${{ format('{0}-latest', matrix.os) }}", "ubuntu-latest"},
		{"integration disabled", "integration.yml", "  integration:\n", "  integration:\n    if: false\n"},
		{"test condition changed", "integration.yml", "if: success() || failure()", "if: success()"},
		{"race disabled", "integration.yml", "race: true", "race: false"},
		{"32-bit disabled", "integration.yml", "use32bit: true", "use32bit: false"},
		{"test failure tolerated", "integration.yml", "      - name: Run tools tests\n", "      - name: Run tools tests\n        continue-on-error: true\n"},
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
