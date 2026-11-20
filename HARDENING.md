<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.3.0** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): the composite action's pwsh run: block puts a GitHub Actions expression straight into the script: `if ('${{ runner.os }}' -ne 'Windows') {` and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'`. Any ${{ }} inside a run: script counts as script injection. Read it from $env:RUNNER_OS instead.

Locations:

- `action.yml:182`
- `action.yml:183`

### script-injection (severity: high)

Rule (b): workflow-controlled input is passed to a second interpreter without escaping. inputs.arch goes into ARG_ARCH, then $Arch. Normalize-Arch passes any value it doesn't recognise through unchanged. That value is then placed inside a cmd.exe /s /c command string: `$json = $(& "${env:COMSPEC}" /s /c "`"$script_path`" -arch=$Arch -no_logo && pwsh -Command ...")`. cmd.exe parses the string, so an arch value containing '&', '|' or similar runs arbitrary commands. Check $Arch against an allowlist (e.g. x86, amd64, x64, arm, arm64) before using it.

Locations:

- `action.yml:137`

### github-env-injection (severity: high)

Every environment variable added or changed by the VS dev shell setup is written to GITHUB_ENV with no newline stripping: `$added + $modified | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. The modified values (e.g. PATH, INCLUDE, LIB) include the environment inherited from the calling workflow, and the setup is driven by inputs.arch. A value containing a newline could therefore inject extra NAME=VALUE entries into GITHUB_ENV. Strip CR/LF from each value before writing (e.g. `$v = $_.Value -replace "[`r`n]", ''`). The other option is to write each value between heredoc delimiters generated with [guid]::NewGuid().

Locations:

- `action.yml:214`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

action.yml: (1) Swapped the inline runner.os expressions for $env:RUNNER_OS. (2) Do-Setup now checks the normalized arch against the allowlist ^(x86|amd64|x64|arm|arm64)$ (case-insensitive) before it reaches Enter-VsDevShell or the cmd.exe /s /c command string. Unknown values throw. Upstream passed them through, and VsDevCmd would reject them anyway. The check only runs on Windows, as before. (3) GITHUB_ENV writes now use the heredoc form with a [guid]::NewGuid() delimiter for each variable, so values are kept unchanged and can't inject extra entries. CR/LF is stripped from variable names.

