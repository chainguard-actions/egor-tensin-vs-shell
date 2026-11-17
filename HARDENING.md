<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--vs-shell/v2.2.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--vs-shell/v2.2.3** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): a GitHub Actions expression is put straight into the pwsh run: script in action.yml: `if ('${{ runner.os }}' -ne 'Windows') {` (line 146) and `echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'` (line 147). Template substitution happens before PowerShell parses the script. Fix: read $env:RUNNER_OS instead. A related problem on line 132: the workflow-controlled input arch (ARG_ARCH -> $Arch) is inserted into a command line that cmd.exe runs with `& "${env:COMSPEC}" /s /c "`"$script_path`" -arch=$Arch -no_logo && ..."`. cmd metacharacters in the arch input, such as & or |, would be run by cmd. Fix: check $Arch against an allowlist (x86, x64, arm64, amd64) before using it.

Locations:

- `action.yml:146`
- `action.yml:147`
- `action.yml:132`

### github-env-injection (severity: high)

The composite step writes every process environment variable to $GITHUB_ENV with no sanitization: `Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }`. This includes ARG_ARCH, which comes from inputs.arch, and any env vars inherited from the calling workflow. A value with embedded newlines can add extra variables such as NODE_OPTIONS or LD_PRELOAD to later steps. Fix: strip CR/LF from each value before writing (e.g. `$_.Value -replace '[\r\n]',''`), or use a heredoc block with a delimiter from [guid]::NewGuid(), and only write variables that are new or changed.

Locations:

- `action.yml:175`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yml b/action.yml
index 726420f..dd1a680 100644
--- a/action.yml
+++ b/action.yml
@@ -10,6 +10,23 @@ inputs:
 runs:
   using: composite
   steps:
     - env:
         ARG_ARCH: ${{ inputs.arch }}
       run: |
@@ -143,8 +160,8 @@ runs:
             }
         }
 
-        if ('${{ runner.os }}' -ne 'Windows') {
-            echo 'Not going to set up a Visual Studio shell on ${{ runner.os }}'
+        if ($env:RUNNER_OS -ne 'Windows') {
+            echo "Not going to set up a Visual Studio shell on $env:RUNNER_OS"
         } else {
             $old_values = @{}
             Get-ChildItem env: | %{ $old_values.Add($_.Name, $_.Value) }
@@ -171,8 +188,16 @@ runs:
             echo '----------------------------------------------------------------'
             $new_values.GetEnumerator() | where { $old_values.ContainsKey($_.Name) -and $old_values[$_.Name] -ne $_.Value } | Format-List
 
-            # Update the current environment:
-            Get-ChildItem env: | %{ echo "$($_.Name)=$($_.Value)" >> $env:GITHUB_ENV }
+            # Update $GITHUB_ENV with only new/modified variables introduced by the VS
+            # setup (sanitize values to strip newlines before writing).
+            # Writing only the diff prevents attacker-controlled env vars (e.g. ARG_ARCH)
+            # and other inherited caller env vars from being injected into $GITHUB_ENV.
+            $new_values.GetEnumerator() | where {
+                -not $old_values.ContainsKey($_.Name) -or $old_values[$_.Name] -ne $_.Value
+            } | %{
+                $sanitizedValue = $_.Value -replace "`r", "" -replace "`n", ""
+                echo "$($_.Name)=$sanitizedValue" >> $env:GITHUB_ENV
+            }
         }
       shell: pwsh
 

```

Locations:

- `action.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, prior-fix

**Notes:**

I fixed all three findings in action.yml. Nothing was run or tested.

- **script-injection:** The pwsh script no longer pastes `${{ runner.os }}` into its text. It reads `$env:RUNNER_OS` instead. The `arch` input is now checked after it is normalized (Win32 becomes x86, arm becomes arm64). Only x86, x64, amd64, arm and arm64 are allowed, matched without regard to case. Any other value makes the step fail with an error before it reaches the cmd.exe command line.
- **github-env-injection:** Instead of writing every environment variable to `$GITHUB_ENV`, the step now writes only the ones the Visual Studio setup added or changed. Line breaks are removed from each value first.
- **prior-fix:** This is the same set of changes the previous harden made. I put them back.

Two behaviour changes from upstream:
- An `arch` value outside the allowed list now fails the step. Upstream passed it straight through.
- Later steps no longer inherit environment variables the Visual Studio setup didn't touch. One example is a variable set in this step's own `env:` block, such as `ARG_ARCH`.

