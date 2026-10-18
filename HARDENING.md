<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2.3** was hardened automatically. 2 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Two `${{ runner.os }}` expressions are interpolated directly inside the `run:` PowerShell script block. Any `${{ ... }}` expression inside a `run:` block is a script-injection risk because YAML template substitution occurs before the shell ever sees the value. The offending lines are: `if ('${{ runner.os }}' -ne 'Windows') {` and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. These should be replaced with the environment variable `$env:RUNNER_OS` which is already available in the runner environment.

Locations:

- `action.yml:143`
- `action.yml:144`

### github-env-injection (severity: high)

Case (e): The step dumps ALL environment variables — including any inherited from the calling workflow — directly into `$GITHUB_ENV` without sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. Any env var set by the calling workflow (e.g. containing newlines or `key=value` injection payloads) will be written unsanitized to `$GITHUB_ENV`, allowing an attacker to inject arbitrary environment variables into subsequent steps. The required sanitization (`printf '%s' ... | tr -d '\n\r'`, or PowerShell equivalent) is absent before every write.

Locations:

- `action.yml:163`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

1. script-injection (lines 143-144): Replaced both `${{ runner.os }}` template expressions in the PowerShell run block with `$env:RUNNER_OS`. Also changed the single-quoted string to a double-quoted string so PowerShell interpolates the variable correctly in the echo message. 2. github-env-injection (line 163): Added PowerShell sanitization using `-replace` to strip carriage returns and newlines from each environment variable value before writing it to $GITHUB_ENV. The loop now captures the sanitized value in `$sanitizedValue` and writes that instead of the raw `$_.Value`.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection finding in action.yml by changing the final environment variable write loop to only propagate variables that are NEW or MODIFIED by the VS setup process (the diff between $old_values captured before VS setup and $new_values captured after). Previously, the action wrote ALL environment variables to $GITHUB_ENV, including attacker-controlled ARG_ARCH (set from inputs.arch) and any other env vars inherited from the calling workflow. The fix reuses the existing $old_values/$new_values infrastructure (already used for diagnostics) to filter the $GITHUB_ENV writes to only VS-specific changes. Newline sanitization via PowerShell -replace is preserved.

