package ci

import (
	"crypto/sha1"
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
		if n.Tag == "!!merge" || (n.Tag != "" && !strings.HasPrefix(n.Tag, "!!")) {
			return fmt.Errorf("YAML merges and custom tags are not supported")
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

func validate(files map[string][]byte) error { return validateWorkflowProperties(files) }

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

// Полные пакеты не делятся по функциям. Независимый набор ниже фиксирует все
// исходные 18 self-вариантов, шесть вспомогательных пар и пять benchmark-запусков.
func integrationMatrixSet(jobs map[string]any, name string, fields []string) (map[string]bool, error) {
	minimum, latest, err := moduleGoVersions()
	if err != nil {
		return nil, err
	}
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
				if field == "go" {
					if value == minimum {
						value = "minimum"
					} else if value == latest {
						value = "latest"
					}
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
		name   string
		fields []string
		cases  map[string]bool
	}{
		{
			"integration",
			[]string{"os", "go", "race", "use32bit", "mode", "version"},
			integrationCaseSet(
				"ubuntu|minimum|false|false|v1|1",
				"ubuntu|minimum|false|false|v2|2",
				"ubuntu|minimum|false|false|gso|1",
				"ubuntu|minimum|false|false|ecn|1",
				"ubuntu|latest|false|false|v1|1",
				"ubuntu|latest|false|false|v2|2",
				"ubuntu|latest|false|false|gso|1",
				"ubuntu|latest|false|false|ecn|1",
				"ubuntu|latest|true|false|v1|1",
				"ubuntu|latest|true|false|gso|1",
				"ubuntu|latest|false|true|v1|1",
				"ubuntu|latest|false|true|v2|2",
				"ubuntu|latest|false|true|gso|1",
				"ubuntu|latest|false|true|ecn|1",
				"windows|latest|false|false|v1|1",
				"windows|latest|false|false|v2|2",
				"macos|latest|false|false|v1|1",
				"macos|latest|false|false|v2|2",
			),
		},
		{
			"ancillary",
			[]string{"os", "go", "race", "use32bit"},
			integrationCaseSet(
				"ubuntu|minimum|false|false",
				"ubuntu|latest|false|false",
				"ubuntu|latest|true|false",
				"ubuntu|latest|false|true",
				"windows|latest|false|false",
				"macos|latest|false|false",
			),
		},
		{
			"benchmarks",
			[]string{"os", "go", "race", "use32bit"},
			integrationCaseSet(
				"ubuntu|minimum|false|false",
				"ubuntu|latest|false|false",
				"ubuntu|latest|false|true",
				"windows|latest|false|false",
				"macos|latest|false|false",
			),
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
		env, _ := job["env"].(map[string]any)
		if env["DEBUG"] != false || env["TIMESCALE_FACTOR"] != 3 {
			return fmt.Errorf("%s: integration timing or qlog environment changed", policy.name)
		}

	}
	return nil
}

func TestIntegrationUnionRejectsMissingAndRepeatedCases(t *testing.T) {
	for _, name := range []string{"integration", "ancillary", "benchmarks"} {
		for _, mutation := range []string{"missing", "duplicate", "unknown row", "extra axis", "timing"} {
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

				}
				if validateIntegrationUnion(jobs) == nil {
					t.Fatal("independent integration union accepted mutation")
				}
			})
		}
	}
}
