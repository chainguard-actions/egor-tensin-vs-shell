<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2.1** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Three `${{ }}` expressions are directly interpolated inside the `run:` PowerShell script block, before the shell ever sees the value. (1) Line 32: `${{ inputs.arch }}` is attacker-controlled and injected directly into a PowerShell `New-Variable` call — a malicious caller can supply a value containing PowerShell metacharacters to break out of the string context. (2) Line 143: `${{ runner.os }}` is interpolated directly in an `if` condition. (3) Line 144: `${{ runner.os }}` is interpolated directly in an `echo` call. Per the check rules, any `${{ ... }}` expression inside a `run:` block is a finding regardless of which context it reads from. The fix is to pass these values through environment variables and reference them as `$env:ARCH` / `$env:RUNNER_OS` instead.

Locations:

- `action.yml:32`
- `action.yml:143`
- `action.yml:144`

### github-env-injection (severity: high)

Sub-rule (e): Line 168 writes every environment variable from the runner process directly to `$GITHUB_ENV` without any sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. This composite action inherits all env vars set by the calling workflow, which are untrusted. Any of those values could contain newline characters that inject additional key=value pairs into `$GITHUB_ENV`, allowing an attacker to override arbitrary environment variables for subsequent steps. The fix requires sanitizing each value (stripping `\n` and `\r`) before writing it to `$GITHUB_ENV`.

Locations:

- `action.yml:168`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.arch }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection, github-env-injection

**Notes:**

Fixed three findings in hardened/action/action.yml:
1. script-injection / static-inline-injection: Moved `${{ inputs.arch }}` and `${{ runner.os }}` from the PowerShell run block into the step's `env:` map (as ARCH and RUNNER_OS). Updated script references to use `$env:ARCH` and `$env:RUNNER_OS` respectively.
2. github-env-injection: Added PowerShell `-replace '[\r\n]', ''` sanitization for both the name and value of each environment variable before writing to `$GITHUB_ENV`, preventing newline injection attacks.

