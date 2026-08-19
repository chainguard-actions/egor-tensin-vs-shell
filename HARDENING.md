<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2** was hardened automatically. 6 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Three ${{ ... }} expressions are directly interpolated inside the run: shell block in action.yml. (1) `${{ inputs.arch }}` is embedded in a PowerShell string: `New-Variable arch -Value (Normalize-Arch '${{ inputs.arch }}') -Option Constant`. (2) `${{ runner.os }}` appears twice in the same block: `if ('${{ runner.os }}' -ne 'Windows')` and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. All three are YAML template substitutions that occur before the shell processes the string, allowing an attacker-controlled or workflow-controlled value to inject arbitrary PowerShell commands.

Locations:

- `action.yml:13`
- `action.yml:131`
- `action.yml:132`

### github-env-injection (severity: high)

The run: block in action.yml dumps the entire runner environment to $GITHUB_ENV without any sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. This writes all inherited environment variables — including any set by the calling workflow (untrusted) — directly to GITHUB_ENV. A newline embedded in any env var value could inject arbitrary environment variables or override existing ones. The required sanitization step (stripping newlines before each write) is absent.

Locations:

- `action.yml:148`

### unpinned-uses (severity: high)

The workflow uses `actions/checkout@v6`, which is pinned to a mutable tag rather than an immutable 40-character commit SHA. A tag can be moved to point to a different (potentially malicious) commit, enabling a supply-chain attack. It should be replaced with a full SHA pin, e.g. `actions/checkout@<40-char-sha> # v6`.

Locations:

- `.github/workflows/test.yml:60`

### missing-permissions (severity: medium)

The workflow file .github/workflows/test.yml has no top-level `permissions:` key and no job-level `permissions:` key on any job. Without explicit permissions, the workflow inherits the repository default (often `write-all` for private repos or `read-all` for public repos), granting broader access than necessary. A minimal `permissions:` block (e.g. `contents: read`) should be added.

Locations:

- `.github/workflows/test.yml:1`

### script-injection (severity: high)

Sub-rule (a): Two ${{ ... }} expressions are directly interpolated inside run: shell blocks in the workflow file. (1) `(${{ matrix.condition }}) -or $(throw 'Unexpected cl.exe version')` — the matrix `condition` value (a string like `'$version -ge 1930 -and $version -lt 1950'`) is injected directly into a PowerShell run: block, allowing a matrix entry to inject arbitrary PowerShell. (2) `$expected = '${{ matrix.expected_arch }}'` — the matrix `expected_arch` value is injected directly into a PowerShell run: block. Both values flow through YAML template substitution before the shell sees them.

Locations:

- `.github/workflows/test.yml:76`
- `.github/workflows/test.yml:84`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.arch }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all 6 findings across action.yml and .github/workflows/test.yml:

1. action.yml script-injection (lines 13, 131, 132): Moved ${{ inputs.arch }} and ${{ runner.os }} into the step's env: block as INPUT_ARCH and RUNNER_OS_VALUE. Updated all references in the PowerShell script to use $env:INPUT_ARCH and $env:RUNNER_OS_VALUE.

2. action.yml static-inline-injection (line 33): Same fix — Normalize-Arch now receives $env:INPUT_ARCH instead of the interpolated template expression.

3. action.yml github-env-injection (line 148): Sanitized both env var names and values by stripping CR/LF characters using PowerShell's -replace operator before writing to $GITHUB_ENV.

4. test.yml unpinned-uses (line 60): Pinned actions/checkout@v6 to actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.

5. test.yml missing-permissions (line 1): Added top-level permissions: contents: read.

6. test.yml script-injection (lines 76, 84): Moved ${{ matrix.condition }} to env: MATRIX_CONDITION and ${{ matrix.expected_arch }} to env: MATRIX_EXPECTED_ARCH; updated run: blocks to reference these env vars instead.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection issues in action.yml: (1) Quoted the user-controlled $env:INPUT_ARCH argument in the Normalize-Arch function call: `Normalize-Arch "$env:INPUT_ARCH"`. (2) Replaced the double-quoted echo string that interpolated $env:RUNNER_OS_VALUE with a single-quoted string concatenation: `echo ('Not going to set up a Visual Studio shell on ' + $env:RUNNER_OS_VALUE)`, preventing injection via the runner.os context value.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in `.github/workflows/test.yml` (line 91). Replaced `Invoke-Expression $condition` with strict regex-based validation: the condition string from `$env:MATRIX_CONDITION` is matched against two allowlisted patterns (`$version -ge N` and `$version -ge N -and $version -lt M`). Bounds are extracted as integers and evaluated directly with PowerShell comparison operators, eliminating dynamic code execution entirely. All existing matrix condition values are covered by the allowlist patterns.

