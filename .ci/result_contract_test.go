package ci

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompleteResultExecutesOutcomePolicy(t *testing.T) {
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"go_build.yml", "integration.yml"} {
		t.Run(file, func(t *testing.T) {
			workflow, err := parse(workflows(t)[file])
			if err != nil {
				t.Fatal(err)
			}
			gate := workflowJobs(workflow)["gate"].(map[string]any)
			script := ""
			for _, raw := range workflowSteps(gate) {
				step := raw.(map[string]any)
				env, _ := step["env"].(map[string]any)
				if env["NEEDS_RESULTS"] != nil {
					script, _ = step["run"].(string)
				}
			}
			for _, results := range []string{"success", "success,success", "success,success,success", "", "failure", "skipped", "neutral", "cancelled", "success,skipped", "success,", "success,,success", "success,success,failure"} {
				_, err := runContractBash(bash, script, map[string]string{"NEEDS_RESULTS": results})
				want := results != "" && !strings.Contains(results, ",,") && !strings.HasSuffix(results, ",")
				for _, result := range strings.Split(results, ",") {
					want = want && result == "success"
				}
				if (err == nil) != want {
					t.Fatalf("result %q: %v", results, err)
				}
			}
		})
	}
}

func TestWorkflowPropertiesAllowEquivalentEdits(t *testing.T) {
	files := workflows(t)
	for file, raw := range files {
		workflow, err := parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		workflow["name"] = "Clearer purpose"
		for name, raw := range workflowJobs(workflow) {
			job := raw.(map[string]any)
			if !(file == "go_build.yml" && name == "gate") {
				job["name"] = "Clearer purpose"
			}
			job["timeout-minutes"] = 45
			for _, raw := range workflowSteps(job) {
				step := raw.(map[string]any)
				step["name"] = "Clearer description"
				if uses, ok := step["uses"].(string); ok {
					action, _, _ := strings.Cut(uses, "@")
					step["uses"] = action + "@" + strings.Repeat("a", 40)
				}
			}
		}
		encoded, err := yaml.Marshal(workflow)
		if err != nil {
			t.Fatal(err)
		}
		files[file] = encoded
	}
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
}

func TestYAMLReusePreservesValueChecks(t *testing.T) {
	files := workflows(t)
	raw := strings.ReplaceAll(string(files["go_build.yml"]), "\r\n", "\n")
	replace := func(source, old, replacement string) string {
		t.Helper()
		changed := strings.Replace(source, old, replacement, 1)
		if changed == source {
			t.Fatalf("YAML reuse scenario did not apply: %q", old)
		}
		return changed
	}
	raw = replace(raw, `name: "Go Build"`, `name: &title "Go Build"`)
	raw = replace(raw, "    - name: Build", "    - name: *title")
	files["go_build.yml"] = []byte(raw)
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
	raw = replace(raw, "env:\n", "env:\n  CI_ALIAS_IGNORE: &ignored '${{ true }}'\n")
	raw = replace(raw, "  build:\n", "  build:\n    continue-on-error: *ignored\n")
	files["go_build.yml"] = []byte(raw)
	workflow, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatalf("alias scenario must be valid YAML: %v", err)
	}
	if workflowJobs(workflow)["build"].(map[string]any)["continue-on-error"] != "${{ true }}" {
		t.Fatal("alias did not resolve to ignored failure")
	}
	if validate(files) == nil {
		t.Fatal("ignored failure through alias accepted")
	}
}

func TestRequiredWorkCannotBeSkippedOrIgnored(t *testing.T) {
	for _, tc := range []struct {
		name, job, action, field string
		jobLevel                 bool
		value                    any
	}{
		{"checkout skipped", "build", "actions/checkout@", "if", false, false},
		{"compiler skipped", "build", "actions/setup-go@", "if", false, false},
		{"scanner skipped", "security", "", "if", false, false},
		{"scanner failure ignored", "security", "", "continue-on-error", true, "${{ true }}"},
		{"checkout failure ignored", "build", "actions/checkout@", "continue-on-error", false, "${{ true }}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := workflows(t)
			workflow, err := parse(files["go_build.yml"])
			if err != nil {
				t.Fatal(err)
			}
			job := workflowJobs(workflow)[tc.job].(map[string]any)
			if tc.jobLevel {
				job[tc.field] = tc.value
			} else {
				for _, raw := range workflowSteps(job) {
					step := raw.(map[string]any)
					uses, _ := step["uses"].(string)
					if tc.action != "" && strings.HasPrefix(uses, tc.action) || tc.action == "" && step["run"] != nil {
						step[tc.field] = tc.value
					}
				}
			}
			files["go_build.yml"], err = yaml.Marshal(workflow)
			if err != nil {
				t.Fatal(err)
			}
			if validate(files) == nil {
				t.Fatal("required work was skipped or its failure suppressed")
			}
		})
	}
	files := workflows(t)
	workflow, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"build", "security"} {
		job := workflowJobs(workflow)[name].(map[string]any)
		job["continue-on-error"] = "${{ false }}"
		for _, raw := range workflowSteps(job) {
			step := raw.(map[string]any)
			step["if"] = "${{ success() }}"
			step["continue-on-error"] = "${{ false }}"
		}
		job["steps"] = append(workflowSteps(job), map[string]any{
			"run": "printf 'runner diagnostics\\n'", "if": "runner.debug == '1'", "continue-on-error": "${{ true }}",
		})
	}
	files["go_build.yml"], err = yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(files); err != nil {
		t.Fatalf("lawful success admission or optional diagnostics rejected: %v", err)
	}
}
