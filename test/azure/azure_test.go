// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build azure

// Package azure runs examples/azure-windows-server against real Azure: it
// creates a billable VM and deletes its resource group when the test ends,
// pass or fail. It needs az logged in and a conn3x binary:
//
//	CONN3X_BIN=./conn3x go test -tags azure -count=1 -timeout 60m -v ./test/azure/
package azure

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// maxMonthCost is above what a run could reasonably add, under James's limit.
const maxMonthCost = 15.0

const secret = "s3ntinel-azure-example-value"

func az(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "az", args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("az %s: %w: %s", args[0], err, strings.TrimSpace(errOut.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// preflight refuses to spend when it can't see, or doesn't like, what's spent.
func preflight(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sub, err := az(ctx, "account", "show", "--query", "id", "-o", "tsv")
	if err != nil {
		t.Fatal(err)
	}
	cost, err := monthCost(ctx, sub)
	if err != nil {
		t.Fatalf("can't read this month's cost, so not spending more: %v", err)
	}
	t.Logf("month to date: $%.2f", cost)
	if cost >= maxMonthCost {
		t.Fatalf("this month has cost $%.2f, over the $%.0f this test will run above", cost, maxMonthCost)
	}
	used, err := az(ctx, "vm", "list-usage", "-l", "westus2", "--query", "[?name.value=='cores'].[currentValue, limit] | [0]", "-o", "tsv")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(used)
	if len(f) == 2 {
		cur, _ := strconv.Atoi(f[0])
		limit, _ := strconv.Atoi(f[1])
		if limit-cur < 2 {
			t.Fatalf("only %d of %d vCPUs free in westus2", limit-cur, limit)
		}
	}
}

// monthCost reads month-to-date spend. Cost Management throttles hard, and a
// 429 says nothing about the spend, so it retries, then falls back to the
// Consumption API. It errors rather than guess.
func monthCost(ctx context.Context, sub string) (float64, error) {
	var err error
	for try := 1; try <= 3; try++ {
		var out string
		out, err = az(ctx, "rest", "--method", "post",
			"--url", "https://management.azure.com/subscriptions/"+sub+"/providers/Microsoft.CostManagement/query?api-version=2023-03-01",
			"--body", `{"type":"ActualCost","timeframe":"MonthToDate","dataset":{"granularity":"None","aggregation":{"c":{"name":"Cost","function":"Sum"}}}}`,
			"--query", "properties.rows", "-o", "json")
		if err == nil {
			var rows [][]any
			if err := json.Unmarshal([]byte(out), &rows); err != nil {
				return 0, err
			}
			if len(rows) == 0 {
				return 0, nil
			}
			cost, ok := rows[0][0].(float64)
			if !ok {
				return 0, fmt.Errorf("unexpected cost row %v", rows[0])
			}
			return cost, nil
		}
		if !strings.Contains(err.Error(), "Too Many Requests") {
			return 0, err
		}
		time.Sleep(time.Minute)
	}
	// The usage list comes a page at a time; every page counts.
	url := "https://management.azure.com/subscriptions/" + sub + "/providers/Microsoft.Consumption/usageDetails?api-version=2023-05-01"
	var modern, legacy float64
	for page := 0; ; page++ {
		if page == 100 {
			return 0, errors.New("usage runs past 100 pages")
		}
		out, cerr := az(ctx, "rest", "--method", "get", "--url", url,
			"--query", "{next: nextLink, modern: sum(value[].properties.costInBillingCurrency), legacy: sum(value[].properties.cost)}", "-o", "json")
		if cerr != nil {
			return 0, fmt.Errorf("%v; then %v", err, cerr)
		}
		var u struct {
			Next           *string
			Modern, Legacy float64
		}
		if err := json.Unmarshal([]byte(out), &u); err != nil {
			return 0, err
		}
		modern, legacy = modern+u.Modern, legacy+u.Legacy
		if u.Next == nil || *u.Next == "" {
			return max(modern, legacy), nil
		}
		url = *u.Next
	}
}

func myIP(t *testing.T) string {
	t.Helper()
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || strings.Contains(string(b), ":") || len(b) == 0 {
		t.Fatalf("no IPv4 address from ifconfig.me: %q, %v", b, err)
	}
	return strings.TrimSpace(string(b))
}

type run struct {
	t   *testing.T
	bin string
	dir string
	env []string
}

func (r *run) tool(args ...string) (string, int) {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), r.env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return string(out), 0
}

func (r *run) must(args ...string) string {
	r.t.Helper()
	out, code := r.tool(args...)
	if code != 0 {
		r.t.Fatalf("conn3x %s: exit %d\n%s", args[0], code, redact(out))
	}
	return out
}

// redact keeps this test's output free of what it's checking for.
func redact(s string) string { return strings.ReplaceAll(s, secret, "(the secret)") }

// cleanup deletes the run's resource group, and only that, whatever happened.
func cleanup(t *testing.T, r *run, group string) {
	if !strings.HasPrefix(group, "conn3x-ci-win-") {
		t.Fatalf("refusing to delete %q", group)
	}
	if out, code := r.tool("destroy", "-auto-approve", "-no-color", "-input=false"); code != 0 {
		t.Logf("destroy failed, deleting the group anyway: exit %d\n%s", code, redact(out))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	exists, err := az(ctx, "group", "exists", "-n", group)
	if err != nil {
		t.Errorf("checking %s: %v", group, err)
		return
	}
	if exists == "true" {
		if _, err := az(ctx, "group", "delete", "-n", group, "-y"); err != nil {
			t.Errorf("DELETE BY HAND: %s: %v", group, err)
			return
		}
	}
	if exists, err = az(ctx, "group", "exists", "-n", group); err != nil || exists != "false" {
		t.Errorf("DELETE BY HAND: %s still exists: %s, %v", group, exists, err)
	}
}

func TestExample(t *testing.T) {
	bin := os.Getenv("CONN3X_BIN")
	if bin == "" {
		t.Fatal("CONN3X_BIN is not set")
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	preflight(t)
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	group := "conn3x-ci-win-" + hex.EncodeToString(raw)
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../examples/azure-windows-server")); err != nil {
		t.Fatal(err)
	}
	keygen := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", group, "-f", filepath.Join(dir, "admin"))
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	tags, _ := json.Marshal(map[string]string{"conn3x-ci": "true", "created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z")})
	cidrs, _ := json.Marshal([]string{myIP(t) + "/32"})
	pass := make([]byte, 24)
	if _, err := rand.Read(pass); err != nil {
		t.Fatal(err)
	}
	r := &run{t: t, bin: bin, dir: dir, env: []string{
		"CONN3X_HMAC_KEY=" + hex.EncodeToString(pass),
		"TF_VAR_state_passphrase=" + hex.EncodeToString(pass),
		"TF_VAR_app_secret=" + secret,
		"TF_VAR_name=" + group,
		"TF_VAR_tags=" + string(tags),
		"TF_VAR_admin_cidrs=" + string(cidrs),
		"TF_VAR_admin_public_key_file=" + filepath.Join(dir, "admin.pub"),
		"TF_VAR_admin_private_key_file=" + filepath.Join(dir, "admin"),
	}}
	t.Cleanup(func() { cleanup(t, r, group) })

	r.must("init", "-no-color", "-input=false")
	plan := r.must("plan", "-no-color", "-input=false", "-out=tfplan")
	if strings.Contains(plan, secret) {
		t.Error("the secret is in the plan output")
	}
	for _, want := range []string{
		"azurerm_windows_virtual_machine.this will be created",
		`conn3x_windows_feature.windows__web_server["win1"] will be created`,
		`conn3x_windows_reboot.windows__restart_if_needed["win1"] will be created`,
		`conn3x_windows_service.windows__web_running["win1"] will be created`,
		`conn3x_windows_registry_value.windows__long_paths["win1"] will be created`,
		`conn3x_windows_directory.windows__app_dir["win1"] will be created`,
		`conn3x_windows_file.windows__secret["win1"] will be created`,
		`conn3x_windows_acl.windows__network_service_can_read["win1"] will be created`,
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan is missing %q:\n%s", want, redact(plan))
		}
	}
	start := time.Now()
	applied := r.must("apply", "-no-color", "-input=false", "tfplan")
	t.Logf("from nothing to configured in %s", time.Since(start).Round(time.Second))
	if strings.Contains(applied, secret) {
		t.Error("the secret is in the apply output")
	}
	pulled := r.must("state", "pull")
	if strings.Contains(pulled, secret) {
		t.Error("the secret is in state")
	}
	if !strings.Contains(pulled, "hmac-sha256:") {
		t.Error("state has no HMAC of the secret")
	}
	stateFile, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateFile, []byte("private_key_openssh")) {
		t.Error("state on disk isn't encrypted")
	}

	if out, code := r.tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("second plan: exit %d\n%s", code, redact(out))
	}

	ip := strings.TrimSpace(r.must("output", "-raw", "ip"))
	hostKey := strings.TrimSpace(r.must("output", "-raw", "host_key"))
	key, err := os.ReadFile(filepath.Join(dir, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ssh.DialWait(context.Background(), ssh.Config{Host: ip, User: "azadmin", PrivateKey: key, HostKey: hostKey}, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	host := func(script string, args map[string]any) string {
		t.Helper()
		res, err := ps.User(context.Background(), c, script, args, 5*time.Minute)
		if err != nil {
			t.Fatalf("%v\nscript: %s", err, script)
		}
		return strings.TrimSpace(res.Text)
	}
	if got := host(`[IO.File]::ReadAllText('C:\app\secret.txt')`, nil); got != secret {
		t.Error("the secret file doesn't hold the secret")
	}
	secretRules := host(`(Get-Acl -LiteralPath 'C:\app\secret.txt').Sddl`, nil)
	if !strings.Contains(secretRules, "D:P") || strings.Contains(secretRules, "BU") || strings.Contains(secretRules, "WD") {
		t.Errorf("rules on the secret file: %s", secretRules)
	}
	if got := host(`(Get-Service W3SVC).Status.ToString()`, nil); got != "Running" {
		t.Errorf("W3SVC is %s", got)
	}
	// The bootstrap installed this key and removed the others it replaced.
	if got := host(`(Get-Content -LiteralPath 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub' -Raw).Trim()`, nil); !strings.HasPrefix(got, strings.Join(strings.Fields(hostKey)[:2], " ")) {
		t.Errorf("host key on disk: %s", got)
	}
	// The bootstrap reached the VM only inside the extension's command, so
	// there is no script on disk for anyone to have changed before it ran.
	if got := host(`$f = 'C:\AzureData\CustomData.bin'; if ([IO.File]::Exists($f)) { (Get-Item -LiteralPath $f).Length } else { 'none' }`, nil); got != "none" && got != "0" {
		t.Errorf("C:\\AzureData\\CustomData.bin holds %s bytes; the example should pass no custom data", got)
	}
	// None of this landed in a log or a leftover on the host.
	hits := host(`param($A)
$n = @()
foreach ($log in 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell') {
  foreach ($e in @(Get-WinEvent -LogName $log -MaxEvents 2000 -ErrorAction SilentlyContinue)) { if ($e.Message -like "*$($A.s)*") { $n += "$log $($e.Id)" } }
}
foreach ($d in 'C:\WindowsAzure\Logs', 'C:\AzureData', 'C:\Windows\Temp') {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object Length -lt 20MB)) {
    try { if ([IO.File]::ReadAllText($f.FullName).Contains($A.s) -or [IO.File]::ReadAllText($f.FullName).Contains($A.k)) { $n += $f.FullName } } catch {}
  }
}
$n -join ','`, map[string]any{"s": secret, "k": r.privateKeyMarker()})
	if hits != "" {
		t.Errorf("found on the host: %s", hits)
	}

	// Change everything by hand: drift names it, and an apply puts it back.
	host(`[IO.File]::WriteAllText('C:\app\config.json', 'changed by hand')
[IO.File]::WriteAllText('C:\app\secret.txt', 'changed by hand')
Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 0
Stop-Service W3SVC -Force
$s = Get-Acl -LiteralPath 'C:\app'
$s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'), 'Read', 'Allow')))
Set-Acl -LiteralPath 'C:\app' -AclObject $s`, nil)
	drift, code := r.tool("drift", "-no-color", "-input=false")
	if code != 2 {
		t.Errorf("drift: exit %d\n%s", code, redact(drift))
	}
	if strings.Contains(drift, secret) {
		t.Error("the secret is in the drift output")
	}
	for _, want := range []string{"windows__config", "windows__secret", "windows__long_paths", "windows__web_running", "windows__app_dir"} {
		if !strings.Contains(drift, want) {
			t.Errorf("drift doesn't name %s:\n%s", want, redact(drift))
		}
	}
	r.must("apply", "-no-color", "-input=false", "-auto-approve")
	if got := host(`[IO.File]::ReadAllText('C:\app\secret.txt')`, nil); got != secret {
		t.Error("apply didn't restore the secret file")
	}
	if got := host(`(Get-Service W3SVC).Status.ToString()`, nil); got != "Running" {
		t.Errorf("apply didn't restart W3SVC: %s", got)
	}
	if out, code := r.tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after reapply: exit %d\n%s", code, redact(out))
	}

	// A reboot Windows wants, which a failed run would have missed.
	host(`New-Item -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' | Out-Null`, nil)
	before, err := windows.BootID(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	out, code := r.tool("plan", "-no-color", "-input=false", "-detailed-exitcode")
	if code != 2 || !strings.Contains(out, "restart_if_needed") {
		t.Errorf("plan with a pending reboot: exit %d\n%s", code, redact(out))
	}
	// Applying that reboot is covered by test/windows. Clear the marker and
	// reboot here, to show every step is clean once the host has been down.
	host(`Remove-Item -Force -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'`, nil)
	if err := windows.ApplyReboot(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(10 * time.Minute)
	for {
		if time.Now().After(deadline) {
			t.Fatal("the host did not come back")
		}
		time.Sleep(10 * time.Second)
		c2, err := ssh.DialWait(context.Background(), ssh.Config{Host: ip, User: "azadmin", PrivateKey: key, HostKey: hostKey}, time.Minute)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		now, err := windows.BootID(ctx, c2)
		cancel()
		c2.Close()
		if err == nil && now != before {
			break
		}
	}
	if out, code := r.tool("plan", "-no-color", "-input=false", "-detailed-exitcode"); code != 0 {
		t.Errorf("plan after a reboot: exit %d\n%s", code, redact(out))
	}
}

// privateKeyMarker is a line from the middle of the host's private key, to look
// for on the host without ever printing it.
func (r *run) privateKeyMarker() string {
	out, code := r.tool("show", "-json")
	if code != 0 {
		r.t.Fatalf("show: exit %d", code)
	}
	i := bytes.Index([]byte(out), []byte("BEGIN OPENSSH PRIVATE KEY"))
	if i < 0 {
		r.t.Fatal("no host private key in state to look for")
	}
	rest := out[i+len("BEGIN OPENSSH PRIVATE KEY-----\\n"):]
	line, _, _ := strings.Cut(rest, `\n`)
	if len(line) < 40 {
		r.t.Fatal("the host private key isn't in the expected form")
	}
	return line[:40]
}
