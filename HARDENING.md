<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v1** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Four `${{ }}` expressions are interpolated directly inside the `run:` PowerShell block before the shell ever sees the value. Two use the attacker-controllable `inputs.arch` input: line 54 `-DevCmdArguments '-arch=${{ inputs.arch }} -no_logo'` and line 73 `-arch=${{ inputs.arch }} -no_logo`. Two use `runner.os`: line 83 `if ('${{ runner.os }}' -ne 'Windows')` and line 84 `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. Any `${{ ... }}` expression directly inside a `run:` block is a script-injection risk because YAML template substitution occurs before the shell quotes the value, allowing injection of arbitrary PowerShell metacharacters.

Locations:

- `action.yml:54`
- `action.yml:73`
- `action.yml:83`
- `action.yml:84`

### github-env-injection (severity: high)

The `run:` block at line 110 writes every current environment variable — including any inherited from the calling workflow — to `$GITHUB_ENV` without sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. Because composite actions inherit the calling workflow's environment, any workflow-controlled env var containing newlines can inject arbitrary key=value pairs into GITHUB_ENV, enabling environment variable hijacking. The required newline-stripping sanitization is absent before the write.

Locations:

- `action.yml:110`

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

Fixed all four findings in action.yml:
1. Moved `${{ inputs.arch }}` and `${{ runner.os }}` from the run: PowerShell block into the step's env: block as INPUT_ARCH and RUNNER_OS. All references inside the script now use `$env:INPUT_ARCH` and `$env:RUNNER_OS` (safe PowerShell env var references).
2. Sanitized the GITHUB_ENV write by stripping carriage returns and newlines from both key and value using PowerShell's `-replace "`r|`n", ''` before writing, preventing newline-based environment variable injection.
3. The two static-inline-injection findings (lines 56, 77) were the same inputs.arch expressions in Import-PS and Import-CMD functions — fixed by the same env: block approach.

### Iteration 2

**Fixes applied:** unpinned-uses, missing-permissions, script-injection, github-env-injection

**Notes:**

Fixed all four findings:
1. **unpinned-uses** (.github/workflows/test.yml:34): Pinned `actions/checkout@v2` to full commit SHA `ee0669bd1cc54295c223e0bb666b733df41de1c5`.
2. **missing-permissions** (.github/workflows/test.yml:1): Added `permissions: {}` top-level block to restrict default token permissions.
3. **script-injection** (action.yml:57,80): Added allowlist validation for `$arch` in both `Import-PS` and `Import-CMD` functions. The value is checked against `@('x86', 'x64', 'arm', 'arm64')` before being interpolated into PowerShell/cmd strings, preventing injection of subexpressions.
4. **github-env-injection** (action.yml:113): Changed the `$GITHUB_ENV` write loop to only forward environment variables that are **new or modified** after the VS shell setup (using the already-computed `$old_values`/`$new_values` diff), rather than all inherited environment variables. This prevents attacker-controlled inherited env vars from being forwarded to `$GITHUB_ENV`.

