<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--vs-shell/v2.2** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): GitHub Actions expressions are directly interpolated inside the `run:` PowerShell block without going through an env: variable. On line 33, `${{ inputs.arch }}` is interpolated directly into the shell command string: `New-Variable arch -Value (Normalize-Arch '${{ inputs.arch }}') -Option Constant`. An attacker-controlled `inputs.arch` value could inject arbitrary PowerShell. On lines 148–149, `${{ runner.os }}` is interpolated directly: `if ('${{ runner.os }}' -ne 'Windows')` and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. Any `${{ ... }}` expression inside a `run:` block is a script-injection finding — these must be moved to `env:` variables and referenced as `$ENV_VAR` in the shell script.

Locations:

- `action.yml:33`
- `action.yml:148`
- `action.yml:149`

### github-env-injection (severity: high)

Sub-rule (e): The run block bulk-writes ALL environment variables to $GITHUB_ENV without any sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. Because this is a composite action, it inherits the entire environment from the calling workflow, including any workflow-controlled or attacker-influenced env vars. Writing these values to $GITHUB_ENV without applying a sanitization step (e.g., stripping newlines) allows an attacker to inject arbitrary key=value pairs into the GitHub environment file, potentially overwriting sensitive environment variables for subsequent steps. Each value must be sanitized (newlines stripped) before being written to $GITHUB_ENV.

Locations:

- `action.yml:166`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.arch }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all three findings in action.yml:
1. script-injection / static-inline-injection: Moved `${{ inputs.arch }}` out of the run: block into an `env:` variable (INPUT_ARCH), referenced as `$env:INPUT_ARCH` in PowerShell.
2. script-injection: Moved `${{ runner.os }}` out of the run: block into an `env:` variable (RUNNER_OS), referenced as `$env:RUNNER_OS` in PowerShell.
3. github-env-injection: Added newline sanitization using PowerShell's `-replace` operator (`$_.Value -replace "`r`n|`r|`n", ''`) before writing each environment variable value to $GITHUB_ENV, preventing newline injection attacks.

