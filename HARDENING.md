<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2.2** was hardened automatically. 2 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Two `${{ runner.os }}` expressions are directly interpolated inside the `run:` block shell command string (PowerShell). Any `${{ ... }}` expression inside a `run:` block is a script-injection risk because YAML template substitution occurs before the shell ever sees the value. The offending lines are:
  Line 148: `if ('${{ runner.os }}' -ne 'Windows') {`
  Line 149: `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`
These should be replaced with the pre-set environment variable `$env:RUNNER_OS` instead.

Locations:

- `action.yml:148`
- `action.yml:149`

### github-env-injection (severity: high)

The `run:` block at line 163 dumps every environment variable from the runner into `$GITHUB_ENV` without any newline sanitization:
  `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`
This is a composite action that inherits all env vars from the calling workflow. Any workflow-controlled (untrusted) environment variable whose value contains newline characters could inject arbitrary `KEY=VALUE` pairs into the GitHub environment, allowing environment variable hijacking. The required sanitization (equivalent of `tr -d '\n\r'` applied to each value before writing) is absent.

Locations:

- `action.yml:163`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed two findings in hardened/action/action.yml:
1. script-injection: Replaced both `${{ runner.os }}` template expressions with `$env:RUNNER_OS` (the pre-set GitHub Actions runner environment variable). Changed the surrounding single-quoted string to double-quoted so PowerShell interpolates the variable correctly.
2. github-env-injection: Added newline sanitization to the line that writes all environment variables to $GITHUB_ENV. Each value is now sanitized with `-replace '[\r\n]', ''` before being written, preventing newline-based environment variable injection attacks.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Added an allowlist validation for the `$arch` variable in action.yml immediately after the `Normalize-Arch` call. The allowlist contains all known valid VsDevCmd.bat architecture values: x86, x64, arm, arm64, x86_arm, x86_amd64, amd64_x86, amd64_arm, amd64_arm64. If the user-supplied `inputs.arch` value (after normalization) is not in the allowlist, the script throws an error before the value is interpolated into either the `-DevCmdArguments` string (Enter-VsDevShell call) or the cmd.exe invocation string, preventing injection of metacharacters like `&`, `|`, or `&&`.

