<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2** was hardened automatically. 2 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): a GitHub Actions expression is placed directly inside the run: script. Offending lines: `if ('${{ runner.os }}' -ne 'Windows') {` and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. Fix: read the RUNNER_OS environment variable instead ($env:RUNNER_OS).

Locations:

- `action.yml:146`
- `action.yml:147`

### github-env-injection (severity: high)

The step writes every process environment variable to GITHUB_ENV without sanitizing it: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. This includes variables the composite action inherits from the calling workflow and ARG_ARCH, which comes from inputs.arch. None of these values has newlines (\n, \r) removed before the write. A multi-line value could therefore inject extra environment variables, for example NODE_OPTIONS or a PATH override, into later steps. Fix: remove \n and \r from each name and value before writing, or only write the variables that the VS dev shell actually changed, after sanitizing them.

Locations:

- `action.yml:175`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

I fixed both findings in action.yml. The step runs under pwsh, so I used PowerShell syntax. I haven't run the action, so neither change has been tested.

1. **script-injection:** The two `${{ runner.os }}` expressions in the script now read `$env:RUNNER_OS` instead. The message line now uses double quotes so PowerShell fills in the variable.
2. **github-env-injection:** Before each environment variable is written to `$GITHUB_ENV`, carriage returns and newlines are now stripped from its name and its value. The action still writes every variable, as upstream did.

**Behaviour change:** if a variable's value really spans several lines, its lines are now joined into one line. Upstream wrote such values in a way that broke them anyway, so nothing that worked before should be affected. If you want multi-line values kept intact, the alternative is to write them with a random per-run delimiter instead of stripping the newlines.

