package ci

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var immutableAction = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
var cancelableResultCondition = regexp.MustCompile(`^(?:always\s*\(\s*\)\s*&&\s*)?!\s*cancelled\s*\(\s*\)(?:\s*&&\s*always\s*\(\s*\))?$`)
var nativeGoEnvironment = map[string]string{
	"GOFLAGS": "", "GOENV": "off", "GOTOOLCHAIN": "local", "GOOS": "", "GOARCH": "",
}

func moduleGoVersions() (string, string, error) {
	module, err := os.ReadFile("../go.mod")
	if err != nil {
		return "", "", err
	}
	version := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+)\.([0-9]+)\r?$`).FindSubmatch(module)
	if version == nil {
		return "", "", fmt.Errorf("module must declare its minimum Go version")
	}
	return string(version[1]) + "." + string(version[2]), string(version[1]) + ".x", nil
}

func workflowJobs(w map[string]any) map[string]any {
	jobs, _ := w["jobs"].(map[string]any)
	return jobs
}

func workflowSteps(job map[string]any) []any { steps, _ := job["steps"].([]any); return steps }

func dependencyNames(value any) []string {
	if name, ok := value.(string); ok {
		return []string{name}
	}
	var names []string
	values, _ := value.([]any)
	for _, raw := range values {
		names = append(names, fmt.Sprint(raw))
	}
	slices.Sort(names)
	return names
}

func readOnlyToken(value any) error {
	if value == nil {
		return nil
	}
	permissions, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("checks require explicitly read-only permissions")
	}
	for _, capability := range permissions {
		if capability != "read" && capability != "none" {
			return fmt.Errorf("checks may not acquire write capability")
		}
	}
	return nil
}

func preservesFailure(value any) bool {
	return value == nil || value == false || value == "${{ false }}"
}

// These forms retain GitHub's default success admission. Other conditions cannot
// prove that required work executes; this check does not evaluate expressions.
func requiredStepAdmission(value any) bool {
	return value == nil || value == true || value == "success()" || value == "${{ success() }}" || value == "${{ true }}"
}

// These documented forms execute after failures and stop with workflow cancellation.
// Extra conditions can skip a required result; this does not evaluate expressions.
func cancelableResultAdmission(value any) bool {
	expression, ok := value.(string)
	if !ok {
		return false
	}
	expression = strings.TrimSpace(expression)
	if strings.HasPrefix(expression, "${{") {
		if !strings.HasSuffix(expression, "}}") {
			return false
		}
		expression = strings.TrimSpace(expression[3 : len(expression)-2])
	}
	return cancelableResultCondition.MatchString(expression)
}

func requiredConsumer(script string) bool {
	return strings.Contains(script, "go build ") || strings.Contains(script, "go test ") ||
		strings.Contains(script, "go run ") || strings.Contains(script, "ci/run-native-tests.sh") ||
		strings.Contains(script, "scan --scanners")
}

func sourcePreparation(job map[string]any) error {
	if !preservesFailure(job["continue-on-error"]) || !requiredStepAdmission(job["if"]) {
		return fmt.Errorf("required job may not be disabled or ignored")
	}
	if err := readOnlyToken(job["permissions"]); err != nil {
		return err
	}
	defaults, _ := job["defaults"].(map[string]any)
	run, _ := defaults["run"].(map[string]any)
	if run["working-directory"] != nil || run["shell"] != nil && run["shell"] != "bash" {
		return fmt.Errorf("commands must use Bash from this checkout")
	}
	checkedOut, goReady := false, false
	for _, raw := range workflowSteps(job) {
		step, _ := raw.(map[string]any)
		if directory, ok := step["working-directory"].(string); ok && path.Clean(directory) != "." {
			return fmt.Errorf("command must consume this checkout")
		}
		if step["shell"] != nil && step["shell"] != "bash" {
			return fmt.Errorf("command must use the tested Bash semantics")
		}
		uses, _ := step["uses"].(string)
		script, _ := step["run"].(string)
		if strings.HasPrefix(uses, "actions/checkout@") || strings.HasPrefix(uses, "actions/setup-go@") || requiredConsumer(script) {
			if !requiredStepAdmission(step["if"]) || !preservesFailure(step["continue-on-error"]) {
				return fmt.Errorf("required preparation and commands must execute and preserve failures")
			}
		}
		if uses != "" && !strings.HasPrefix(uses, "./") && !immutableAction.MatchString(uses) {
			return fmt.Errorf("external actions require immutable commits")
		}
		with, _ := step["with"].(map[string]any)
		if strings.HasPrefix(uses, "actions/checkout@") {
			if with["persist-credentials"] != false {
				return fmt.Errorf("checkout may not persist credentials")
			}
			for key, expected := range map[string]any{"ref": "${{ github.sha }}", "repository": "${{ github.repository }}", "path": ".", "sparse-checkout": nil} {
				value := with[key]
				if key == "path" && value != nil {
					location, ok := value.(string)
					if !ok {
						return fmt.Errorf("invalid checkout path")
					}
					value = path.Clean(location)
				}
				if value != nil && value != expected {
					return fmt.Errorf("checkout %s must preserve the complete caller commit", key)
				}
			}
			checkedOut = true
		}
		if strings.HasPrefix(uses, "actions/setup-go@") {
			if !checkedOut {
				return fmt.Errorf("Go setup must follow checkout")
			}
			goReady = true
		}
		if script, ok := step["run"].(string); ok {
			if !checkedOut {
				return fmt.Errorf("commands must follow checkout")
			}
			if (strings.Contains(script, "go ") || strings.Contains(script, "ci/run-native-tests.sh")) && !goReady {
				return fmt.Errorf("Go commands must use the prepared compiler")
			}
		}
	}
	return nil
}

func resultGraph(workflow map[string]any) error {
	jobs := workflowJobs(workflow)
	gate, ok := jobs["gate"].(map[string]any)
	if !ok {
		return fmt.Errorf("complete result missing")
	}
	var expected []string
	for name := range jobs {
		if name != "gate" {
			expected = append(expected, name)
		}
	}
	slices.Sort(expected)
	if !slices.Equal(dependencyNames(gate["needs"]), expected) || len(expected) == 0 {
		return fmt.Errorf("every job must influence the complete result")
	}
	if !cancelableResultAdmission(gate["if"]) || !preservesFailure(gate["continue-on-error"]) {
		return fmt.Errorf("result must evaluate failures and stop with workflow cancellation")
	}
	steps := workflowSteps(gate)
	if len(steps) == 0 {
		return fmt.Errorf("result evaluation missing")
	}
	for _, raw := range steps {
		step := raw.(map[string]any)
		env, _ := step["env"].(map[string]any)
		if env["NEEDS_RESULTS"] == "${{ join(needs.*.result, ',') }}" && requiredStepAdmission(step["if"]) && preservesFailure(step["continue-on-error"]) && step["shell"] == "bash" {
			return nil
		}
	}
	return fmt.Errorf("result must read all actual dependency outcomes")
}

func validateWorkflowProperties(files map[string][]byte) error {
	root, err := parse(files["go_build.yml"])
	if err != nil {
		return err
	}
	on, _ := root["on"].(map[string]any)
	for _, event := range []string{"pull_request", "merge_group"} {
		if value, exists := on[event]; !exists || value != nil {
			return fmt.Errorf("%s must run without exclusions", event)
		}
	}
	push, _ := on["push"].(map[string]any)
	if !slices.Contains(dependencyNames(push["branches"]), "main") || push["paths"] != nil || push["paths-ignore"] != nil {
		return fmt.Errorf("main push must evaluate the complete graph")
	}
	concurrency, _ := root["concurrency"].(map[string]any)
	if concurrency["group"] != "${{ github.workflow }}-${{ github.repository }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}" || concurrency["cancel-in-progress"] != "${{ github.event_name == 'pull_request' }}" {
		return fmt.Errorf("only superseded PR work may be cancelled")
	}
	if err := resultGraph(root); err != nil {
		return err
	}
	if workflowJobs(root)["gate"].(map[string]any)["name"] != "CI" {
		return fmt.Errorf("required CI context must report the complete result")
	}
	for _, role := range []string{"build", "contract", "security", "govulncheck"} {
		if _, ok := workflowJobs(root)[role].(map[string]any); !ok {
			return fmt.Errorf("%s check missing", role)
		}
	}
	for role, file := range map[string]string{"ginkgo": "ginkgo_test.yml", "integration": "integration.yml"} {
		caller, _ := workflowJobs(root)[role].(map[string]any)
		if caller["uses"] != "./.github/workflows/"+file || !requiredStepAdmission(caller["if"]) || !preservesFailure(caller["continue-on-error"]) || caller["with"] != nil {
			return fmt.Errorf("%s must call the same-commit complete checks", role)
		}
	}
	minimum, latest, err := moduleGoVersions()
	if err != nil {
		return err
	}
	for file, data := range files {
		workflow, err := parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if file != "go_build.yml" && file != "ginkgo_test.yml" && file != "integration.yml" {
			events, ok := workflow["on"].(map[string]any)
			if !ok {
				return fmt.Errorf("invalid workflow events")
			}
			for _, event := range []string{"push", "pull_request", "pull_request_target", "merge_group"} {
				if _, exists := events[event]; exists {
					return fmt.Errorf("merge checks must affect the required result")
				}
			}
			for name, raw := range workflowJobs(workflow) {
				job := raw.(map[string]any)
				if strings.EqualFold(name, "CI") || job["name"] == "CI" {
					return fmt.Errorf("required CI context belongs to go_build.yml")
				}
			}
			continue
		}
		if workflow["permissions"] == nil {
			return fmt.Errorf("%s must explicitly request a read-only token", file)
		}
		if err := readOnlyToken(workflow["permissions"]); err != nil {
			return err
		}
		defaults, _ := workflow["defaults"].(map[string]any)
		run, _ := defaults["run"].(map[string]any)
		if run["shell"] != "bash" || run["working-directory"] != nil {
			return fmt.Errorf("native commands must use Bash from the checkout root")
		}
		environment, _ := workflow["env"].(map[string]any)
		for key, expected := range nativeGoEnvironment {
			if environment[key] != expected {
				return fmt.Errorf("native compiler target and scope must not inherit runner %s", key)
			}
		}
		if file != "go_build.yml" {
			events, ok := workflow["on"].(map[string]any)
			if !ok {
				return fmt.Errorf("invalid workflow admission")
			}
			if _, exists := events["workflow_call"]; !exists || len(events) != 1 {
				return fmt.Errorf("worker must have only same-commit workflow_call admission")
			}
		}
		for name, raw := range workflowJobs(workflow) {
			job, _ := raw.(map[string]any)
			if !preservesFailure(job["continue-on-error"]) {
				return fmt.Errorf("required job failure may not be ignored")
			}
			if err := readOnlyToken(job["permissions"]); err != nil {
				return err
			}
			env, _ := job["env"].(map[string]any)
			for key, expected := range nativeGoEnvironment {
				if env[key] != nil && env[key] != expected {
					return fmt.Errorf("%s must preserve declared Go configuration", key)
				}
			}
			if name == "gate" {
				continue
			}
			if job["uses"] != nil {
				continue
			}
			if name != "build" && name != "contract" && name != "security" && name != "govulncheck" && name != "integration" && name != "ancillary" && name != "benchmarks" {
				for _, raw := range workflowSteps(job) {
					step := raw.(map[string]any)
					uses, _ := step["uses"].(string)
					if !preservesFailure(step["continue-on-error"]) || uses != "" && !strings.HasPrefix(uses, "./") && !immutableAction.MatchString(uses) {
						return fmt.Errorf("additional checks must preserve failures and immutable actions")
					}
				}
				continue
			}
			if err := sourcePreparation(job); err != nil {
				return fmt.Errorf("%s/%s: %w", file, name, err)
			}
			for _, raw := range workflowSteps(job) {
				step := raw.(map[string]any)
				env, _ := step["env"].(map[string]any)
				for key, expected := range nativeGoEnvironment {
					if env[key] != nil && env[key] != expected {
						return fmt.Errorf("%s must preserve declared Go configuration", key)
					}
				}
				uses, _ := step["uses"].(string)
				if strings.HasPrefix(uses, "actions/setup-go@") {
					with, _ := step["with"].(map[string]any)
					if name == "build" || file == "integration.yml" {
						if with["go-version"] != "${{ matrix.go }}" {
							return fmt.Errorf("matrix must select the checked compiler")
						}
					} else if with["go-version"] != latest {
						return fmt.Errorf("control checks must follow the module's supported Go minor")
					}
				}
			}
		}
	}
	for file, osValues := range map[string][]string{"go_build.yml": {"ubuntu-latest", "windows-latest", "macos-latest"}, "ginkgo_test.yml": nil} {
		workflow, _ := parse(files[file])
		job, _ := workflowJobs(workflow)["build"].(map[string]any)
		strategy, _ := job["strategy"].(map[string]any)
		matrix, _ := strategy["matrix"].(map[string]any)
		if strategy["fail-fast"] != false || !slices.Equal(dependencyNames(matrix["go"]), []string{minimum, latest}) {
			return fmt.Errorf("native checks must cover minimum and current patch compilers")
		}
		if osValues != nil {
			slices.Sort(osValues)
			if !slices.Equal(dependencyNames(matrix["os"]), osValues) || job["runs-on"] != "${{ matrix.os }}" {
				return fmt.Errorf("build must use every native OS")
			}
		} else if job["runs-on"] != "ubuntu-latest" {
			return fmt.Errorf("unit suites must use their native Linux environment")
		}
	}
	integration, err := parse(files["integration.yml"])
	if err != nil {
		return err
	}
	if err := resultGraph(integration); err != nil {
		return err
	}
	for _, name := range []string{"integration", "ancillary", "benchmarks"} {
		if workflowJobs(integration)[name].(map[string]any)["runs-on"] != "${{ format('{0}-latest', matrix.os) }}" {
			return fmt.Errorf("integration must use its matrix OS")
		}
	}
	return validateIntegrationUnion(workflowJobs(integration))
}

func TestNewJobMustInfluenceResult(t *testing.T) {
	files := workflows(t)
	workflow, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	jobs := workflowJobs(workflow)
	jobs["future-check"] = map[string]any{"runs-on": "ubuntu-latest", "steps": []any{map[string]any{"run": "true"}}}
	if resultGraph(workflow) == nil {
		t.Fatal("new check bypassed CI")
	}
	gate := jobs["gate"].(map[string]any)
	gate["needs"] = append(gate["needs"].([]any), "future-check")
	if err := resultGraph(workflow); err != nil {
		t.Fatal(err)
	}
}
