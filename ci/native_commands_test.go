package ci

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func goFlags(flags *flag.FlagSet, args []string) ([]string, error) {
	var operands []string
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			operands = append(operands, args[i])
			continue
		}
		name, value, assigned := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		option := flags.Lookup(name)
		if option == nil {
			return nil, fmt.Errorf("unqualified Go flag %s", args[i])
		}
		if !assigned {
			if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
				value = "true"
			} else {
				i++
				if i == len(args) {
					return nil, fmt.Errorf("missing %s value", name)
				}
				value = args[i]
			}
		}
		if err := flags.Set(name, value); err != nil {
			return nil, err
		}
	}
	return operands, nil
}

func goCommandProblems(args []string, suite string, row map[string]any) error {
	if len(args) == 0 {
		return fmt.Errorf("Go was not invoked")
	}
	flags := flag.NewFlagSet("native", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Bool("v", false, "")
	flags.Bool("json", false, "")
	if suite == "ginkgo" {
		if args[0] != "run" || len(args) < 2 || args[1] != "github.com/onsi/ginkgo/v2/ginkgo" {
			return fmt.Errorf("unit suites must use their Ginkgo runner")
		}
		recursive := flags.Bool("r", false, "")
		flags.BoolVar(recursive, "recursive", false, "")
		cover := flags.Bool("cover", false, "")
		randomize := flags.Bool("randomize-all", false, "")
		suites := flags.Bool("randomize-suites", false, "")
		skip := flags.String("skip-package", "", "")
		flags.Bool("trace", false, "")
		operands, err := goFlags(flags, args[2:])
		if err != nil {
			return err
		}
		if !*recursive || !*cover || !*randomize || !*suites || *skip != "integrationtests" || len(operands) != 0 {
			return fmt.Errorf("Ginkgo must run every non-integration package with coverage and randomized order")
		}
		return nil
	}
	if suite == "govulncheck" {
		if len(args) < 3 || args[0] != "run" || !regexp.MustCompile(`^golang.org/x/vuln/cmd/govulncheck@v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(args[1]) {
			return fmt.Errorf("reachable vulnerability scan must use a pinned tool")
		}
		if !slices.Equal(args[2:], []string{"./..."}) {
			return fmt.Errorf("reachable vulnerability scan must cover every package")
		}
		return nil
	}
	verb := "test"
	if suite == "build" {
		verb = "build"
	}
	if args[0] != verb {
		return fmt.Errorf("%s must invoke go %s", suite, verb)
	}
	race := flags.Bool("race", false, "")
	count := flags.Int("count", 0, "")
	run := flags.String("run", "", "")
	short := flags.Bool("short", false, "")
	skip := flags.String("skip", "", "")
	bench := flags.String("bench", "", "")
	shuffle := flags.String("shuffle", "off", "")
	timeout := flags.Duration("timeout", 10*time.Minute, "")
	version := flags.Int("version", 0, "")
	flags.Bool("qlog", false, "")
	packages, err := goFlags(flags, args[1:])
	if err != nil {
		return err
	}
	packageName := map[string]string{"build": "./...", "contract": "./ci", "chrome": ".", "self": "./integrationtests/self", "tools": "./integrationtests/tools/...", "versionnegotiation": "./integrationtests/versionnegotiation", "benchmarks": "./integrationtests/self"}[suite]
	if !slices.Equal(packages, []string{packageName}) || *short || *skip != "" {
		return fmt.Errorf("%s must execute its complete package scope", suite)
	}
	if suite == "build" {
		return nil
	}
	if *count != 1 || *timeout <= 0 {
		return fmt.Errorf("tests must execute once now and have a finite deadline")
	}
	if suite == "chrome" {
		if *run != "TestChrome146_DifferentialAgainstRealChrome" {
			return fmt.Errorf("Chrome differential check must execute")
		}
		return nil
	}
	if suite == "contract" {
		if *run != "" {
			return fmt.Errorf("CI properties may not be filtered")
		}
		return nil
	}
	if *race != (row["race"] == true) {
		return fmt.Errorf("race detector must match the matrix case")
	}
	if *shuffle == "off" {
		return fmt.Errorf("protocol ordering must remain randomized")
	}
	if suite == "benchmarks" {
		if *run != "^$" || *bench != "." {
			return fmt.Errorf("benchmark job must measure all benchmarks")
		}
	} else if *run != "" || *bench != "" {
		return fmt.Errorf("protocol tests may not be selected or replaced by benchmarks")
	}
	if suite == "self" && *version != row["version"].(int) {
		return fmt.Errorf("QUIC version must match its matrix row")
	}
	return nil
}

func nativeCallStep(job map[string]any, suite string) (map[string]any, error) {
	prefix := "bash ci/run-native-tests.sh " + suite
	for _, raw := range workflowSteps(job) {
		step := raw.(map[string]any)
		if script, ok := step["run"].(string); ok && strings.Contains(script, prefix) {
			if !requiredStepAdmission(step["if"]) || !preservesFailure(step["continue-on-error"]) {
				return nil, fmt.Errorf("%s must execute for the complete applicable result", suite)
			}
			return step, nil
		}
	}
	return nil, fmt.Errorf("native %s invocation missing", suite)
}

func TestNativeMatrixArgumentsAndEnvironment(t *testing.T) {
	workflow, err := parse(workflows(t)["integration.yml"])
	if err != nil {
		t.Fatal(err)
	}
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for jobName, suites := range map[string][]string{"integration": {"self"}, "ancillary": {"tools", "versionnegotiation"}, "benchmarks": {"benchmarks"}} {
		job := workflowJobs(workflow)[jobName].(map[string]any)
		env := job["env"].(map[string]any)
		for key, expression := range map[string]string{"QUIC_CI_RACE": "${{ matrix.race }}", "QUIC_CI_32BIT": "${{ matrix.use32bit }}"} {
			if env[key] != expression {
				t.Fatalf("%s must bind %s to its matrix", jobName, key)
			}
		}
		if jobName == "integration" && (env["QUIC_CI_MODE"] != "${{ matrix.mode }}" || env["QUIC_CI_VERSION"] != "${{ matrix.version }}") {
			t.Fatal("protocol mode/version binding lost")
		}
		matrix := job["strategy"].(map[string]any)["matrix"].(map[string]any)
		for index, raw := range matrix["include"].([]any) {
			row := raw.(map[string]any)
			for _, suite := range suites {
				t.Run(fmt.Sprintf("%s/%d/%s", jobName, index, suite), func(t *testing.T) {
					step, err := nativeCallStep(job, suite)
					if err != nil {
						t.Fatal(err)
					}
					for _, fail := range []bool{false, true} {
						dir := t.TempDir()
						log := bashPath(filepath.Join(dir, "argv"))
						state := bashPath(filepath.Join(dir, "environment"))
						stub := `go() { printf '%s\0' "$@" > "$UQUIC_ARGUMENTS"; printf '%s|%s|%s|%s|%s|%s' "${GOOS:-}" "${GOARCH:-}" "${QUIC_GO_DISABLE_GSO:-}" "${QUIC_GO_DISABLE_ECN:-}" "$GOFLAGS" "$GOENV" > "$UQUIC_ENVIRONMENT"; if [ "$UQUIC_FAIL" = true ];then return 23;fi; }; export -f go
`
						values := map[string]string{"UQUIC_ARGUMENTS": log, "UQUIC_ENVIRONMENT": state, "UQUIC_FAIL": fmt.Sprint(fail), "QUIC_CI_RACE": fmt.Sprint(row["race"]), "QUIC_CI_32BIT": fmt.Sprint(row["use32bit"]), "QUIC_CI_MODE": "", "QUIC_CI_VERSION": "", "DEBUG": "false", "TIMESCALE_FACTOR": "3", "GOOS": "plan9", "GOARCH": "arm", "GOFLAGS": "-run=Nothing", "GOENV": "poison", "QUIC_GO_DISABLE_GSO": "true", "QUIC_GO_DISABLE_ECN": "true"}
						if jobName == "integration" {
							values["QUIC_CI_MODE"] = fmt.Sprint(row["mode"])
							values["QUIC_CI_VERSION"] = fmt.Sprint(row["version"])
						}
						output, runErr := runContractBash(bash, "cd '"+bashPath(repository)+"'\n"+stub+step["run"].(string), values)
						if (runErr != nil) != fail {
							t.Fatalf("Go failure=%t: %v %s", fail, runErr, output)
						}
						data, err := os.ReadFile(filepath.Join(dir, "argv"))
						if err != nil {
							t.Fatal(err)
						}
						args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
						if err := goCommandProblems(args, suite, row); err != nil {
							t.Fatal(err)
						}
						actual, err := os.ReadFile(filepath.Join(dir, "environment"))
						if err != nil {
							t.Fatal(err)
						}
						arch, gso, ecn := "", "", ""
						if row["use32bit"] == true {
							arch = "386"
						}
						if row["mode"] == "gso" {
							gso = "true"
						}
						if row["mode"] == "ecn" {
							ecn = "true"
						}
						if string(actual) != strings.Join([]string{"", arch, gso, ecn, "", "off"}, "|") {
							t.Fatalf("wrong native environment: %s", actual)
						}
					}
				})
			}
		}
	}
}

func TestNativeFlagProperties(t *testing.T) {
	row := map[string]any{"race": true, "version": 2}
	for _, args := range [][]string{{"test", "./integrationtests/self", "-race=true", "-count", "1", "-shuffle=on", "-version=2"}, {"test", "-version", "2", "-count=1", "-race", "-shuffle", "on", "./integrationtests/self"}} {
		if err := goCommandProblems(args, "self", row); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"test", "-count=1", "-shuffle=on", "-version=2", "./integrationtests/self"}, {"test", "-count=1", "-race", "-shuffle=on", "-version=2", "-run=OneTest", "./integrationtests/self"}, {"test", "-count=1", "-race", "-shuffle=on", "-version=1", "./integrationtests/self"}} {
		if goCommandProblems(args, "self", row) == nil {
			t.Fatal("native execution property lost")
		}
	}
}

func TestBuildUnitAndVulnerabilityCommands(t *testing.T) {
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ file, job, prefix, suite string }{
		{"go_build.yml", "build", "go build ", "build"},
		{"go_build.yml", "contract", "go test ", "contract"},
		{"ginkgo_test.yml", "build", "go test ", "chrome"},
		{"ginkgo_test.yml", "build", "go run ", "ginkgo"},
		{"go_build.yml", "govulncheck", "go run ", "govulncheck"},
	} {
		t.Run(tc.suite, func(t *testing.T) {
			workflow, err := parse(workflows(t)[tc.file])
			if err != nil {
				t.Fatal(err)
			}
			job := workflowJobs(workflow)[tc.job].(map[string]any)
			var selected map[string]any
			for _, raw := range workflowSteps(job) {
				step := raw.(map[string]any)
				if script, ok := step["run"].(string); ok {
					for _, line := range strings.Split(script, "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), tc.prefix) {
							selected = step
						}
					}
				}
			}
			if selected == nil || !requiredStepAdmission(selected["if"]) || !preservesFailure(selected["continue-on-error"]) {
				t.Fatal("required native command must execute")
			}
			for _, mode := range []string{"healthy", "fail-root", "fail-nested"} {
				if mode == "fail-nested" && tc.suite != "govulncheck" {
					continue
				}
				dir := t.TempDir()
				root := bashPath(repository)
				fixture := bashPath(dir)
				stub := `go() {
  count=$(cat "$UQUIC_FIXTURE/count" 2>/dev/null || echo 0);count=$((count+1));printf '%s' "$count" > "$UQUIC_FIXTURE/count"
  printf '%s\0' "$@" > "$UQUIC_FIXTURE/args-$count"
  printf '%s' "$PWD" > "$UQUIC_FIXTURE/cwd-$count"
  printf '%s|%s|%s|%s|%s' "${GOOS:-}" "${GOARCH:-}" "$GOFLAGS" "$GOENV" "$GOTOOLCHAIN" > "$UQUIC_FIXTURE/environment-$count"
  printf '%s' "${TIMESCALE_FACTOR:-}" > "$UQUIC_FIXTURE/timing"
  case "$UQUIC_MODE:$count" in fail-root:1|fail-nested:2) return 23;;esac
}
`
				values := map[string]string{"UQUIC_FIXTURE": fixture, "UQUIC_MODE": mode, "GOOS": "plan9", "GOARCH": "arm", "GOFLAGS": "-run=Nothing", "GOENV": "poison", "GOTOOLCHAIN": "auto"}
				for _, layer := range []map[string]any{workflow, job, selected} {
					env, _ := layer["env"].(map[string]any)
					for key, value := range env {
						values[key] = fmt.Sprint(value)
					}
				}
				output, runErr := runContractBash(bash, "cd '"+root+"'\n"+stub+selected["run"].(string), values)
				if (runErr == nil) != (mode == "healthy") {
					t.Fatalf("%s: %v %s", mode, runErr, output)
				}
				expected := 1
				if tc.suite == "govulncheck" && mode != "fail-root" {
					expected = 2
				}
				count, err := os.ReadFile(filepath.Join(dir, "count"))
				if err != nil || string(count) != fmt.Sprint(expected) {
					t.Fatalf("commands not executed: %s %v", count, err)
				}
				for number := 1; number <= expected; number++ {
					data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("args-%d", number)))
					if err != nil {
						t.Fatal(err)
					}
					args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
					if err := goCommandProblems(args, tc.suite, nil); err != nil {
						t.Fatal(err)
					}
					cwd, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("cwd-%d", number)))
					if err != nil {
						t.Fatal(err)
					}
					expectedRoot := root
					if number == 2 {
						expectedRoot += "/integrationtests/gomodvendor"
					}
					if string(cwd) != expectedRoot {
						t.Fatal("command read a different checkout/module")
					}
					environment, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("environment-%d", number)))
					if err != nil || string(environment) != "|||off|local" {
						t.Fatal("native target or scope inherited runner configuration")
					}
				}
				if tc.suite == "ginkgo" {
					timing, err := os.ReadFile(filepath.Join(dir, "timing"))
					if err != nil || string(timing) != "10" {
						t.Fatal("unit suite timing scale lost")
					}
				}
			}
		})
	}
}
