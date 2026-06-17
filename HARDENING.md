<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--vs-shell/v1** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Four GitHub Actions expressions are directly interpolated inside the run: PowerShell script block, before the shell processes the string. (1) Line 55: `-DevCmdArguments '-arch=${{ inputs.arch }} -no_logo'` — the user-controlled `inputs.arch` value is injected directly into a PowerShell string passed as a command argument, enabling command injection. (2) Line 75: `-arch=${{ inputs.arch }} -no_logo` — same input injected into a cmd.exe invocation string. (3) Line 83: `if ('${{ runner.os }}' -ne 'Windows')` — runner.os is interpolated into a PowerShell comparison. (4) Line 84: `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'` — runner.os interpolated into an echo. All four must be replaced with env: variables and safe shell variable references.

Locations:

- `action.yml:55`
- `action.yml:75`
- `action.yml:83`
- `action.yml:84`

### github-env-injection (severity: high)

Line 113 writes every environment variable (including those inherited from the calling workflow, which are untrusted) to $GITHUB_ENV without any newline sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. An environment variable value containing a newline character could inject additional arbitrary key=value pairs into GITHUB_ENV, allowing an attacker to set arbitrary environment variables for subsequent steps. The required sanitization (`printf '%s' ... | tr -d '\n\r'` or equivalent) is absent.

Locations:

- `action.yml:113`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.arch }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:56`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.arch }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:77`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Rewrote action.yml to fix all findings: (1) Moved ${{ inputs.arch }} out of the run: block into env: INPUT_ARCH, then referenced it as $arch = $env:INPUT_ARCH in both Import-PS and Import-CMD functions. (2) Moved ${{ runner.os }} out of the run: block into env: RUNNER_OS_VAL, then referenced it as $runnerOs = $env:RUNNER_OS_VAL for the OS check and echo. (3) Fixed the GITHUB_ENV injection by sanitizing both variable names and values with PowerShell's -replace operator to strip carriage returns and newlines before writing to $GITHUB_ENV.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in action.yml at both locations (lines 57 and 76):
1. In Import-PS: Added allowlist validation of $arch against @('x64', 'x86', 'arm', 'arm64') before it is interpolated into the -DevCmdArguments string passed to Enter-VsDevShell.
2. In Import-CMD: Added the same allowlist validation of $arch before it is interpolated into the cmd.exe command string.
Both functions now throw an error with a descriptive message if the arch value is not one of the known valid architectures, preventing injection of PowerShell or cmd.exe metacharacters.

