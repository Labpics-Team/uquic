package ci

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type nativeScenario struct {
	suite string
	step  map[string]any
	row   map[string]any
}

func macOSCompilerID(job map[string]any) (string, error) {
	id := ""
	for _, raw := range workflowSteps(job) {
		step := raw.(map[string]any)
		uses, _ := step["uses"].(string)
		if strings.HasPrefix(uses, "actions/setup-go@") {
			next, _ := step["id"].(string)
			if id != "" || !regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_-]*$").MatchString(next) {
				return "", fmt.Errorf("macOS needs one identifiable compiler preparation")
			}
			id = next
		}
	}
	if id == "" {
		return "", fmt.Errorf("macOS compiler preparation missing")
	}
	return id, nil
}

// Recognize the native condition whose only dependencies are cancellation,
// successful preparation and the typed lane selector. In particular, success()
// would silently skip siblings after a failed scenario.
func preparedScenarioAdmission(value any, compilerID string, integration bool) bool {
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
	pattern := "^!\\s*cancelled\\s*\\(\\s*\\)\\s*&&\\s*steps\\." + regexp.QuoteMeta(compilerID) + "\\.outcome\\s*==\\s*'success'"
	if integration {
		pattern += "\\s*&&\\s*matrix\\.integration"
	}
	return regexp.MustCompile(pattern + "$").MatchString(expression)
}

func macOSScenarios(job map[string]any) ([]nativeScenario, error) {
	if job == nil || job["runs-on"] != "macos-latest" {
		return nil, fmt.Errorf("macOS must retain its native arm64 hosted environment")
	}
	strategy, _ := job["strategy"].(map[string]any)
	if strategy["max-parallel"] != 1 {
		return nil, fmt.Errorf("macOS must request at most one compiler lane at a time")
	}
	lanes, err := integrationMatrixSet(map[string]any{"macos": job}, "macos", []string{"go", "integration"})
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(lanes, integrationCaseSet("minimum|false", "latest|true")) {
		return nil, fmt.Errorf("macOS must build both compilers and run integration on the current patch")
	}
	compilerID, err := macOSCompilerID(job)
	if err != nil {
		return nil, err
	}
	env, _ := job["env"].(map[string]any)
	native := map[string]any{"DEBUG": false, "TIMESCALE_FACTOR": 3, "QUIC_CI_RACE": false, "QUIC_CI_32BIT": false}
	for key, expected := range native {
		if env[key] != expected {
			return nil, fmt.Errorf("macOS must preserve %s", key)
		}
	}
	var scenarios []nativeScenario
	for _, raw := range workflowSteps(job) {
		step := raw.(map[string]any)
		script, _ := step["run"].(string)
		if !requiredConsumer(script) {
			continue
		}
		suite, count := "", 0
		for candidate, prefix := range map[string]string{
			"build": "go build ", "self": "bash ci/run-native-tests.sh self",
			"tools":              "bash ci/run-native-tests.sh tools",
			"versionnegotiation": "bash ci/run-native-tests.sh versionnegotiation",
			"benchmarks":         "bash ci/run-native-tests.sh benchmarks",
		} {
			if n := strings.Count(script, prefix); n > 0 {
				suite, count = candidate, count+n
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("each macOS step must expose one independent native invocation")
		}
		if !preparedScenarioAdmission(step["if"], compilerID, suite != "build") || !preservesFailure(step["continue-on-error"]) {
			return nil, fmt.Errorf("macOS scenarios must execute independently after preparation and preserve failures")
		}
		stepEnv, _ := step["env"].(map[string]any)
		for key, expected := range native {
			if value := stepEnv[key]; value != nil && value != expected {
				return nil, fmt.Errorf("macOS scenario changed %s", key)
			}
		}
		row := map[string]any{"race": false, "use32bit": false}
		if suite == "self" {
			mode, modeOK := stepEnv["QUIC_CI_MODE"].(string)
			version, versionOK := stepEnv["QUIC_CI_VERSION"].(int)
			if !modeOK || !versionOK {
				return nil, fmt.Errorf("macOS protocol mode/version must be explicit typed step values")
			}
			row["mode"], row["version"] = mode, version
		}
		scenarios = append(scenarios, nativeScenario{suite, step, row})
	}
	return scenarios, nil
}

func macOSIntegrationCases(jobs map[string]any) (map[string]map[string]bool, error) {
	job, _ := jobs["macos"].(map[string]any)
	scenarios, err := macOSScenarios(job)
	if err != nil {
		return nil, err
	}
	cases := map[string]map[string]bool{"integration": {}, "ancillary": {}, "benchmarks": {}}
	seen := make(map[string]bool)
	const tuple = "macos|latest|false|false"
	for _, scenario := range scenarios {
		key := scenario.suite
		if scenario.suite == "self" {
			key += "|" + fmt.Sprint(scenario.row["mode"]) + "|" + fmt.Sprint(scenario.row["version"])
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate macOS invocation %s", key)
		}
		seen[key] = true
		switch scenario.suite {
		case "self":
			cases["integration"][tuple+"|"+fmt.Sprint(scenario.row["mode"])+"|"+fmt.Sprint(scenario.row["version"])] = true
		case "benchmarks":
			cases["benchmarks"][tuple] = true
		}
	}
	if !seen["build"] || !seen["tools"] || !seen["versionnegotiation"] {
		return nil, fmt.Errorf("macOS builds and the complete ancillary pair must execute")
	}
	cases["ancillary"][tuple] = true
	return cases, nil
}

func TestMacOSLanesRejectMissingOrWeakenedWork(t *testing.T) {
	for _, mutation := range []string{
		"missing compiler", "duplicate compiler", "wrong compiler", "wrong OS",
		"parallel allocations", "fail fast", "skipped lane", "ignored lane",
		"compiler skipped", "compiler overridden", "missing scenario", "duplicate scenario",
		"implicit success", "sibling success", "ignored scenario", "wrong protocol",
		"wrong target", "shorter timing", "missing result",
	} {
		t.Run(mutation, func(t *testing.T) {
			files := workflows(t)
			workflow, err := parse(files["integration.yml"])
			if err != nil {
				t.Fatal(err)
			}
			job := workflowJobs(workflow)["macos"].(map[string]any)
			strategy := job["strategy"].(map[string]any)
			matrix := strategy["matrix"].(map[string]any)
			rows := matrix["include"].([]any)
			scenarios, err := macOSScenarios(job)
			if err != nil {
				t.Fatal(err)
			}
			var protocol map[string]any
			for _, scenario := range scenarios {
				if scenario.suite == "self" && scenario.row["version"] == 1 {
					protocol = scenario.step
				}
			}
			if protocol == nil {
				t.Fatal("required v1 protocol scenario missing")
			}
			switch mutation {
			case "missing compiler":
				matrix["include"] = rows[1:]
			case "duplicate compiler":
				matrix["include"] = append(rows, rows[0])
			case "wrong compiler":
				rows[0].(map[string]any)["go"] = "unsupported"
			case "wrong OS":
				job["runs-on"] = "macos-26-intel"
			case "parallel allocations":
				strategy["max-parallel"] = 2
			case "fail fast":
				strategy["fail-fast"] = true
			case "skipped lane":
				job["if"] = false
			case "ignored lane":
				job["continue-on-error"] = true
			case "compiler skipped", "compiler overridden":
				for _, raw := range workflowSteps(job) {
					step := raw.(map[string]any)
					uses, _ := step["uses"].(string)
					if strings.HasPrefix(uses, "actions/setup-go@") {
						if mutation == "compiler skipped" {
							step["if"] = false
						} else {
							step["with"].(map[string]any)["go-version"] = "unsupported"
						}
					}
				}
			case "missing scenario":
				protocol["run"] = "echo omitted"
			case "duplicate scenario":
				job["steps"] = append(workflowSteps(job), protocol)
			case "implicit success":
				delete(protocol, "if")
			case "sibling success":
				protocol["if"] = strings.Replace(protocol["if"].(string), "!cancelled()", "!cancelled() && success()", 1)
			case "ignored scenario":
				protocol["continue-on-error"] = true
			case "wrong protocol":
				protocol["env"].(map[string]any)["QUIC_CI_VERSION"] = 2
			case "wrong target":
				protocol["env"].(map[string]any)["GOARCH"] = "amd64"
			case "shorter timing":
				job["env"].(map[string]any)["TIMESCALE_FACTOR"] = 1
			case "missing result":
				workflowJobs(workflow)["gate"].(map[string]any)["needs"] = []any{"integration", "ancillary", "benchmarks"}
			}
			files["integration.yml"], err = yaml.Marshal(workflow)
			if err != nil {
				t.Fatal(err)
			}
			if validate(files) == nil {
				t.Fatal("macOS coverage or native failure semantics were lost")
			}
		})
	}
}

func TestMacOSPreparationIdentityCanChange(t *testing.T) {
	files := workflows(t)
	workflow, err := parse(files["integration.yml"])
	if err != nil {
		t.Fatal(err)
	}
	job := workflowJobs(workflow)["macos"].(map[string]any)
	old, err := macOSCompilerID(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range workflowSteps(job) {
		step := raw.(map[string]any)
		if step["id"] == old {
			step["id"] = "ready_go"
		}
		if condition, ok := step["if"].(string); ok {
			step["if"] = strings.ReplaceAll(condition, "steps."+old+".", "steps.ready_go.")
		}
	}
	files["integration.yml"], err = yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
}
