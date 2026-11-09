package ci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func bashPath(location string) string {
	result := filepath.ToSlash(location)
	if volume := filepath.VolumeName(location); volume != "" {
		result = "/" + strings.ToLower(volume[:1]) + strings.TrimPrefix(result, volume)
	}
	return result
}

func optionValues(args []string, option string) []string {
	var values []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], option+"=") {
			values = append(values, strings.TrimPrefix(args[i], option+"="))
		} else if args[i] == option && i+1 < len(args) {
			i++
			values = append(values, args[i])
		}
	}
	return values
}

func scalarOption(args []string, option string) string {
	values := optionValues(args, option)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func boolOption(args []string, option string) bool {
	value := false
	for _, arg := range args {
		if arg == option {
			value = true
		} else if strings.HasPrefix(arg, option+"=") {
			value = strings.TrimPrefix(arg, option+"=") == "true"
		}
	}
	return value
}

func sliceOption(args []string, option string) []string {
	var result []string
	for _, value := range optionValues(args, option) {
		parts, err := csv.NewReader(strings.NewReader(value)).Read()
		if err != nil {
			continue
		}
		for _, part := range parts {
			if part != "" {
				result = append(result, part)
			}
		}
	}
	return result
}

func containsAll(values []string, required ...string) bool {
	for _, value := range required {
		if !slices.Contains(values, value) {
			return false
		}
	}
	return true
}

func scanInvocationProblems(args []string, root, toolDir string) error {
	if len(args) == 0 || args[0] != "fs" {
		return fmt.Errorf("scanner must inspect the filesystem")
	}
	if scalarOption(args, "--config") != "/dev/null" || scalarOption(args, "--exit-code") != "1" {
		return fmt.Errorf("scanner policy must be independent and blocking")
	}
	if len(sliceOption(args, "--skip-dirs"))+len(sliceOption(args, "--skip-files"))+len(sliceOption(args, "--ignore-status")) != 0 {
		return fmt.Errorf("scanner may not skip repository content or findings")
	}
	if policy := scalarOption(args, "--ignore-policy"); policy != "" && policy != "/dev/null" {
		return fmt.Errorf("findings may only be accepted by the reviewed ignore file")
	}
	if path.Clean(scalarOption(args, "--cache-dir")) != path.Clean(toolDir+"/cache") {
		return fmt.Errorf("scanner must use its own cache")
	}
	scanners := sliceOption(args, "--scanners")
	severity := sliceOption(args, "--severity")
	if slices.Contains(scanners, "vuln") {
		if !containsAll(severity, "UNKNOWN", "HIGH", "CRITICAL") || !boolOption(args, "--include-dev-deps") {
			return fmt.Errorf("dependency scan must include relevant severities and development dependencies")
		}
	}
	if slices.Contains(scanners, "secret") && len(severity) > 0 && !containsAll(severity, "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL") {
		return fmt.Errorf("secret scan must retain every severity")
	}
	target := path.Clean(args[len(args)-1])
	if target != "." && target != path.Clean(root) && !strings.HasSuffix(target, "/secret-probe") {
		return fmt.Errorf("scan must consume this checkout or its control fixture")
	}
	return nil
}

func securityScript(t *testing.T) string {
	t.Helper()
	workflow, err := parse(workflows(t)["go_build.yml"])
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range workflowSteps(workflowJobs(workflow)["security"].(map[string]any)) {
		if script, ok := raw.(map[string]any)["run"].(string); ok && strings.Contains(script, "tar -") {
			return script
		}
	}
	t.Fatal("scanner implementation missing")
	return ""
}

func TestSecurityExecutesCompletePolicy(t *testing.T) {
	script := securityScript(t)
	for _, mode := range []string{"healthy", "checksum-error", "dependency-finding", "fixed-finding", "secret-finding", "probe-missed", "probe-tool-error", "modified-key"} {
		t.Run(mode, func(t *testing.T) {
			if err := runSecurityFixture(t, script, mode); (err == nil) != (mode == "healthy") {
				t.Fatalf("%s: %v", mode, err)
			}
		})
	}
	t.Run("equivalent options and immutable update", func(t *testing.T) {
		lawful := strings.ReplaceAll(script, "--config /dev/null", "--config=/dev/null")
		lawful = strings.ReplaceAll(lawful, "--severity UNKNOWN,HIGH,CRITICAL", "--severity HIGH --severity UNKNOWN,CRITICAL")
		lawful = strings.ReplaceAll(lawful, `tar -xzf "$dir/trivy.tgz" -C "$dir" trivy`, `tar --directory="$dir/." --extract --gzip --file="$dir/./trivy.tgz" trivy`)
		lawful = strings.ReplaceAll(lawful, "sha256sum -c -", "sha256sum --check --strict -")
		lawful = strings.ReplaceAll(lawful, "version=0.74.0", "version=9.9.9")
		lawful = regexp.MustCompile(`sum=[a-f0-9]{64}`).ReplaceAllString(lawful, "sum="+strings.Repeat("a", 64))
		if err := runSecurityFixture(t, lawful, "healthy"); err != nil {
			t.Fatal(err)
		}
	})
	for name, mutant := range map[string]string{
		"runner config inherited":     strings.Replace(script, `unset "${!TRIVY_@}"`, ":", 1),
		"repository config inherited": strings.ReplaceAll(script, "--config /dev/null", ""),
		"dev dependencies skipped":    strings.ReplaceAll(script, "--include-dev-deps", "--include-dev-deps=false"),
		"secret severities narrowed":  strings.ReplaceAll(script, "--scanners secret", "--scanners secret --severity HIGH,CRITICAL"),
		"repository subtree skipped":  strings.ReplaceAll(script, "--no-progress", "--no-progress --skip-dirs internal"),
		"finding exit masked":         strings.ReplaceAll(script, "--exit-code 1", "--exit-code 1 --exit-code=0"),
		"released fix ignored":        strings.Replace(script, "--ignore-unfixed --ignorefile /dev/null", `--ignore-unfixed "${accepted[@]}"`, 1),
		"checksum bypassed":           strings.Replace(script, "| sha256sum -c -", "| cat >/dev/null", 1),
		"checksum not checked":        strings.Replace(script, "sha256sum -c -", "sha256sum", 1),
		"different archive checked":   strings.Replace(script, `echo "$sum  $dir/trivy.tgz"`, `echo "$sum  $UQUIC_FIXTURE/archive.tar.gz"`, 1),
		"download digest trusted":     strings.Replace(script, `echo "$sum  $dir/trivy.tgz"`, `echo "$UQUIC_FIXTURE_DIGEST  $dir/trivy.tgz"`, 1),
		"different archive extracted": strings.Replace(script, `tar -xzf "$dir/trivy.tgz"`, `tar -xzf "$UQUIC_FIXTURE/archive.tar.gz"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if mutant == script {
				t.Fatal("counterexample did not apply")
			}
			if err := runSecurityFixture(t, mutant, "healthy"); err == nil {
				t.Fatal("scanner property lost")
			}
		})
	}
}

func runSecurityFixture(t *testing.T, script, mode string) error {
	t.Helper()
	dir := t.TempDir()
	root := bashPath(dir)
	for _, sub := range []string{"bin", "runner", "internal/testdata", "calls"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".trivyignore.yaml", "internal/testdata/priv.key"} {
		data, err := os.ReadFile("../" + name)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "modified-key" && strings.HasSuffix(name, "priv.key") {
			data = append(data, 'x')
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commands := map[string]string{
		"curl": `printf '%s\0' "$@" > "$UQUIC_FIXTURE/calls/curl"
out=
while [ "$#" -gt 0 ]; do case "$1" in -o|--output) out=$2;shift;; --output=*) out=${1#*=};; esac;shift;done
test -n "$out"
cp "$UQUIC_FIXTURE/archive.tar.gz" "$out"
printf '%s\n' "$out" > "$UQUIC_FIXTURE/calls/download"
`,
		"sha256sum": `cat > "$UQUIC_FIXTURE/calls/checksum"
read -r sum archive < "$UQUIC_FIXTURE/calls/checksum"
test "$sum" = "$UQUIC_PINNED_CHECKSUM"
printf '%s  %s\n' "$UQUIC_FIXTURE_DIGEST" "$archive" > "$UQUIC_FIXTURE/calls/fixture-checksum"
if [ "$UQUIC_MODE" = checksum-error ];then printf corrupt >> "$(cat "$UQUIC_FIXTURE/calls/download")";fi
# GNU checksum --strict is meaningful only in verification mode, so the real
# tool rejects hashing without --check, while accepting lawful option forms.
"$UQUIC_REAL_SHA256SUM" "$@" --strict < "$UQUIC_FIXTURE/calls/fixture-checksum"
[[ "$sum" =~ ^[a-f0-9]{64}$ ]]
test "$(readlink -m "$archive")" = "$(readlink -m "$(cat "$UQUIC_FIXTURE/calls/download")")"
printf '%s\n' "$archive" > "$UQUIC_FIXTURE/calls/verified"
`,
		"tar": `"$UQUIC_REAL_TAR" --checkpoint=1 '--checkpoint-action=exec=readlink -m "$TAR_ARCHIVE" > "$UQUIC_FIXTURE/calls/extracted"' "$@"
`,
		"openssl": `out=
while [ "$#" -gt 0 ]; do if [ "$1" = -out ]; then out=$2;shift;fi;shift;done
test -n "$out";printf '%s\n' '-----BEGIN PRIVATE KEY-----' fixture > "$out"
`,
		"trivy": `number=$(cat "$UQUIC_FIXTURE/calls/count" 2>/dev/null || echo 0);number=$((number+1))
printf '%s' "$number" > "$UQUIC_FIXTURE/calls/count"
printf '%s\0' "$@" > "$UQUIC_FIXTURE/calls/scan-$number"
printf '%s\n' "${!TRIVY_@}" >> "$UQUIC_FIXTURE/calls/environment"
target=${!#};scanners=;output=
while [ "$#" -gt 0 ];do
  case "$1" in --scanners) scanners="${scanners:+$scanners,}$2";shift;; --scanners=*) scanners="${scanners:+$scanners,}${1#*=}";; --output) output=$2;shift;; --output=*) output=${1#*=};;esac
  shift
done
if [[ "$target" = */secret-probe ]];then
  case "$UQUIC_MODE" in probe-missed) exit 0;;probe-tool-error) echo 'tool unavailable';exit 2;;esac
  printf '{"Results":[{"Target":"docs/probe.md","Secrets":[{"RuleID":"private-key"}]},{"Target":"tests/probe_test.go","Secrets":[{"RuleID":"private-key"}]}]}' > "$output"
  exit 1
fi
case "$UQUIC_MODE:$scanners" in dependency-finding:vuln,misconfig|fixed-finding:vuln|secret-finding:secret) exit 1;;esac
`,
	}
	for name, body := range commands {
		if err := os.WriteFile(filepath.Join(dir, "bin", name), []byte("#!/bin/bash\nset -euo pipefail\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var archiveBytes bytes.Buffer
	compressed := gzip.NewWriter(&archiveBytes)
	packed := tar.NewWriter(compressed)
	scanner := []byte("#!/bin/bash\nset -euo pipefail\n" + commands["trivy"])
	if err := packed.WriteHeader(&tar.Header{Name: "trivy", Mode: 0o755, Size: int64(len(scanner))}); err != nil {
		t.Fatal(err)
	}
	if _, err := packed.Write(scanner); err != nil {
		t.Fatal(err)
	}
	if err := packed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "archive.tar.gz"), archiveBytes.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep the reviewed source pin and prove that it reaches the verifier. Only
	// the checksum input at the CLI boundary adapts to the stand-in archive bytes.
	pinned := regexp.MustCompile(`\b[a-f0-9]{64}\b`).FindString(script)
	if pinned == "" {
		return fmt.Errorf("scanner checksum must be anchored in the reviewed source")
	}
	fixtureDigest := fmt.Sprintf("%x", sha256.Sum256(archiveBytes.Bytes()))
	bash, err := gateBash()
	if err != nil {
		t.Fatal(err)
	}
	prefix := "cd '" + root + "'\nexport UQUIC_REAL_TAR=$(command -v tar) UQUIC_REAL_SHA256SUM=$(command -v sha256sum)\nexport PATH='" + root + "/bin':\"$PATH\"\n"
	if os.PathSeparator == '\\' {
		prefix += "python3() { python \"$@\"; }\n"
	}
	output, runErr := runContractBash(bash, prefix+script, map[string]string{"UQUIC_FIXTURE": root, "UQUIC_MODE": mode, "UQUIC_PINNED_CHECKSUM": pinned, "UQUIC_FIXTURE_DIGEST": fixtureDigest, "RUNNER_TEMP": root + "/runner", "TRIVY_SKIP_DIRS": "internal", "TRIVY_SEVERITY": "CRITICAL"})
	if runErr != nil {
		return fmt.Errorf("%w: %s", runErr, output)
	}
	readArgs := func(name string) []string {
		data, err := os.ReadFile(filepath.Join(dir, "calls", name))
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	}
	curl := readArgs("curl")
	archive := scalarOption(curl, "-o")
	if archive == "" {
		archive = scalarOption(curl, "--output")
	}
	if len(curl) == 0 {
		return fmt.Errorf("scanner download did not execute")
	}
	url := curl[len(curl)-1]
	version := regexp.MustCompile(`/download/v([0-9]+\.[0-9]+\.[0-9]+)/trivy_([0-9]+\.[0-9]+\.[0-9]+)_Linux-64bit.tar.gz$`).FindStringSubmatch(url)
	if version == nil || version[1] != version[2] {
		return fmt.Errorf("scanner archive must use one immutable release")
	}
	checksum, err := os.ReadFile(filepath.Join(dir, "calls/checksum"))
	if err != nil {
		return err
	}
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fields[0]) || path.Clean(fields[1]) != path.Clean(archive) {
		return fmt.Errorf("downloaded archive must be checksum-verified")
	}
	if fields[0] != pinned {
		return fmt.Errorf("checksum must use the reviewed source pin")
	}
	extracted, err := os.ReadFile(filepath.Join(dir, "calls/extracted"))
	if err != nil || path.Clean(strings.TrimSpace(string(extracted))) != path.Clean(archive) {
		return fmt.Errorf("scanner must be extracted from the verified download")
	}
	environment, err := os.ReadFile(filepath.Join(dir, "calls/environment"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(environment)) != "" {
		return fmt.Errorf("scanner inherited runner configuration")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "calls"))
	if err != nil {
		return err
	}
	dependencies, fixed, secrets, probe := false, false, false, false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "scan-") {
			continue
		}
		args := readArgs(entry.Name())
		if err := scanInvocationProblems(args, root, path.Dir(archive)); err != nil {
			return err
		}
		scanners := sliceOption(args, "--scanners")
		target := args[len(args)-1]
		ignore := scalarOption(args, "--ignorefile")
		if strings.HasSuffix(target, "/secret-probe") {
			probe = containsAll(scanners, "secret") && ignore == "/dev/null"
			continue
		}
		if containsAll(scanners, "vuln", "misconfig") && ignore == ".trivyignore.yaml" && !boolOption(args, "--ignore-unfixed") {
			dependencies = true
		}
		if containsAll(scanners, "vuln") && ignore == "/dev/null" && boolOption(args, "--ignore-unfixed") {
			fixed = true
		}
		if containsAll(scanners, "secret") && ignore == ".trivyignore.yaml" {
			location := path.Clean(scalarOption(args, "--secret-config"))
			if !strings.HasPrefix(location, root+"/") {
				return fmt.Errorf("secret policy must use this invocation's configuration")
			}
			config, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(location, root+"/"))))
			if err != nil {
				return err
			}
			var policy struct {
				Disabled []string `yaml:"disable-allow-rules"`
				Allowed  []any    `yaml:"allow-rules"`
				Enabled  []string `yaml:"enable-builtin-rules"`
			}
			if err := yaml.Unmarshal(config, &policy); err != nil {
				return err
			}
			secrets = containsAll(policy.Disabled, "tests", "examples", "markdown") && len(policy.Allowed) == 0 && len(policy.Enabled) == 0
		}
	}
	if !dependencies || !fixed || !secrets || !probe {
		return fmt.Errorf("scanner omitted dependencies, released fixes, unrestricted secrets or controls")
	}
	return nil
}
