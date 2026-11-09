package ci

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Platform-specific files and the supported 32-bit build must remain free of
// OpenPGP in both production and test dependencies, with and without cgo.
var openPGPPlatforms = []string{"linux-amd64", "linux-386", "linux-arm64", "darwin-amd64", "darwin-arm64", "freebsd-amd64", "windows-amd64", "windows-arm64", "openbsd-amd64"}

var immutableAction = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

func validateOpenPGPWorkflow(raw []byte) error {
	workflow, err := parse(raw)
	if err != nil {
		return err
	}
	jobs, _ := workflow["jobs"].(map[string]any)
	job, _ := jobs["openpgp"].(map[string]any)
	if job["if"] != nil || job["continue-on-error"] == true || job["runs-on"] != "ubuntu-latest" {
		return fmt.Errorf("OpenPGP dependency validation must execute and preserve failure")
	}
	if value := job["permissions"]; value != nil {
		permissions, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("OpenPGP inspection requires a read-only token")
		}
		for _, capability := range permissions {
			if capability != "read" && capability != "none" {
				return fmt.Errorf("OpenPGP inspection cannot write")
			}
		}
	}
	defaults, _ := job["defaults"].(map[string]any)
	runDefaults, _ := defaults["run"].(map[string]any)
	if runDefaults["working-directory"] != nil || runDefaults["shell"] != nil && runDefaults["shell"] != "bash" {
		return fmt.Errorf("OpenPGP graph must use Bash from the checkout root")
	}
	module, err := os.ReadFile("../go.mod")
	if err != nil {
		return err
	}
	version := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+)\.[0-9]+\r?$`).FindSubmatch(module)
	if version == nil {
		return fmt.Errorf("module must declare its supported Go version")
	}
	steps, _ := job["steps"].([]any)
	checkedOut, installed := false, false
	script := ""
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		if step["if"] != nil || step["continue-on-error"] == true || step["working-directory"] != nil || step["shell"] != nil && step["shell"] != "bash" {
			return fmt.Errorf("OpenPGP preparation and list command must run against the checkout")
		}
		uses, _ := step["uses"].(string)
		if uses != "" && !strings.HasPrefix(uses, "./") && !immutableAction.MatchString(uses) {
			return fmt.Errorf("OpenPGP external actions must use an immutable commit")
		}
		with, _ := step["with"].(map[string]any)
		switch {
		case strings.HasPrefix(uses, "actions/checkout@"):
			checkedOut = immutableAction.MatchString(uses) && with["persist-credentials"] == false
			for key, equivalent := range map[string]any{"ref": "${{ github.sha }}", "repository": "${{ github.repository }}", "path": ".", "sparse-checkout": nil} {
				value := with[key]
				if key == "path" && value != nil {
					location, ok := value.(string)
					if !ok {
						return fmt.Errorf("checkout path must refer to the repository root")
					}
					value = path.Clean(location)
				}
				if value != nil && value != equivalent {
					return fmt.Errorf("OpenPGP %s must preserve the complete caller checkout", key)
				}
			}
		case strings.HasPrefix(uses, "actions/setup-go@"):
			installed = checkedOut && immutableAction.MatchString(uses) && with["go-version"] == string(version[1])+".x"
		}
		if run, ok := step["run"].(string); ok && strings.Contains(run, "go list") {
			if !installed || script != "" {
				return fmt.Errorf("OpenPGP graph must use the prepared checkout and module toolchain")
			}
			script = run
		}
	}
	if script == "" {
		return fmt.Errorf("OpenPGP dependency graph command missing")
	}
	return nil
}

func validateOpenPGPBash(script string) error {
	bash, err := gateBash()
	if err != nil {
		return err
	}
	log, err := os.CreateTemp("", "uquic-openpgp-*.calls")
	if err != nil {
		return err
	}
	logPath := log.Name()
	log.Close()
	defer os.Remove(logPath)
	// The shell is real. Only go list is replaced, recording the consumed
	// platform and arguments before supplying healthy, forbidden or failed data.
	const stub = `go() {
  printf '%s|%s\n' "$GOOS-$GOARCH-$CGO_ENABLED" "$*" >> "$UQUIC_OPENPGP_LOG"
  case "$UQUIC_OPENPGP_MODE" in
    forbidden) echo golang.org/x/crypto/openpgp/armor;;
    tool-error) return 17;;
    healthy) echo fmt;;
  esac
}`
	for _, mode := range []string{"healthy", "forbidden", "tool-error"} {
		if err := os.WriteFile(logPath, nil, 0o600); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", stub+"\n"+script)
		cmd.WaitDelay = time.Second
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !slices.Contains([]string{"UQUIC_OPENPGP_LOG", "UQUIC_OPENPGP_MODE", "GOOS", "GOARCH", "CGO_ENABLED"}, key) {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "UQUIC_OPENPGP_LOG="+strings.ReplaceAll(logPath, "\\", "/"), "UQUIC_OPENPGP_MODE="+mode)
		output, runErr := cmd.CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		if timedOut || (runErr == nil) != (mode == "healthy") {
			return fmt.Errorf("OpenPGP %s: error=%v output=%s", mode, runErr, output)
		}
		if mode != "healthy" {
			continue
		}
		observed, err := os.ReadFile(logPath)
		if err != nil {
			return err
		}
		calls := strings.Split(strings.TrimSpace(string(observed)), "\n")
		checked := map[string]bool{}
		for _, call := range calls {
			target, args, valid := strings.Cut(call, "|")
			if !valid {
				return fmt.Errorf("invalid Go-list observation: %s", call)
			}
			if err := openPGPListArguments(strings.Fields(args)); err != nil {
				return err
			}
			checked[target] = true
		}
		for _, platform := range openPGPPlatforms {
			for _, cgo := range []string{"0", "1"} {
				call := platform + "-" + cgo
				if !checked[call] {
					return fmt.Errorf("OpenPGP did not inspect %s", call)
				}
			}
		}
	}
	return nil
}

func openPGPListArguments(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("must inspect the Go dependency graph")
	}
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	deps := flags.Bool("deps", false, "")
	tests := flags.Bool("test", false, "")
	errors := flags.Bool("e", false, "")
	var packages []string
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") {
			packages = append(packages, arg)
			continue
		}
		name, value, assigned := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if !assigned {
			value = "true"
		}
		if err := flags.Set(name, value); err != nil {
			return err
		}
	}
	if !*deps || !*tests || *errors || !slices.Equal(packages, []string{"./..."}) {
		return fmt.Errorf("must resolve every package's production and test dependencies: %q", args)
	}
	return nil
}

func TestOpenPGPDependencyBoundary(t *testing.T) {
	files := workflows(t)
	if err := validateOpenPGPWorkflow(files["go_build.yml"]); err != nil {
		t.Fatal(err)
	}
	workflow, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	steps := workflow["jobs"].(map[string]any)["openpgp"].(map[string]any)["steps"].([]any)
	script := ""
	for _, raw := range steps {
		if run, ok := raw.(map[string]any)["run"].(string); ok && strings.Contains(run, "go list") {
			script = run
		}
	}
	if err := validateOpenPGPBash(script); err != nil {
		t.Fatal(err)
	}
	t.Run("equivalent flag ordering", func(t *testing.T) {
		lawful := strings.ReplaceAll(script, "go list -deps -test ./...", "go list ./... -test=true -deps")
		if err := validateOpenPGPBash(lawful); err != nil {
			t.Fatal(err)
		}
	})
	for name, mutant := range map[string]string{
		"unresolved dependency ignored": strings.Replace(script, `>> "$dependencies"`, `>> "$dependencies" || true`, 1),
		"test dependencies absent":      strings.Replace(script, "-deps -test", "-deps", 1),
		"forbidden package accepted":    strings.Replace(script, "END { exit found }", "END { exit 0 }", 1),
		"platform absent":               strings.Replace(script, " freebsd-amd64", "", 1),
		"code never executed":           "if false; then\n" + script + "\nfi",
	} {
		t.Run(name, func(t *testing.T) {
			if mutant == script {
				t.Fatal("counterexample did not change the source")
			}
			if err := validateOpenPGPBash(mutant); err == nil {
				t.Fatal("dependency property lost")
			}
		})
	}
}

func TestOpenPGPJobAllowsPresentationAndPinnedActionUpdates(t *testing.T) {
	files := workflows(t)
	workflow, err := parse(files["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	job := workflow["jobs"].(map[string]any)["openpgp"].(map[string]any)
	job["name"] = "Dependency graph assurance"
	job["timeout-minutes"] = 20
	for _, raw := range job["steps"].([]any) {
		step := raw.(map[string]any)
		step["name"] = "Clearer purpose"
		if uses, ok := step["uses"].(string); ok {
			action, _, _ := strings.Cut(uses, "@")
			step["uses"] = action + "@" + strings.Repeat("a", 40)
			if action == "actions/checkout" {
				step["with"].(map[string]any)["path"] = "./"
			}
		}
	}
	encoded, err := yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	files["go_build.yml"] = encoded
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
	t.Run("additional external action must be pinned", func(t *testing.T) {
		job["steps"] = append(job["steps"].([]any), map[string]any{"uses": "someone/tool@main"})
		encoded, err := yaml.Marshal(workflow)
		if err != nil {
			t.Fatal(err)
		}
		files["go_build.yml"] = encoded
		if err := validate(files); err == nil {
			t.Fatal("mutable external action was accepted")
		}
	})
}

func TestYAMLAnchorsPreserveWorkflowMeaning(t *testing.T) {
	files := workflows(t)
	files["go_build.yml"] = []byte(strings.Replace(strings.ReplaceAll(string(files["go_build.yml"]), "\r\n", "\n"), `name: "Go Build"`, `name: &workflow_title "Go Build"`, 1))
	files["go_build.yml"] = []byte(strings.Replace(string(files["go_build.yml"]), "name: Проверить отсутствие golang.org/x/crypto/openpgp", "name: *workflow_title", 1))
	if err := validate(files); err != nil {
		t.Fatal(err)
	}
	files["go_build.yml"] = []byte(strings.Replace(string(files["go_build.yml"]), "  openpgp:\n", "  openpgp:\n    continue-on-error: &ignore_failure true\n", 1))
	if err := validate(files); err == nil {
		t.Fatal("anchored ignored failure was accepted")
	}
}
