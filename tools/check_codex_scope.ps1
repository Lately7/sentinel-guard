# Fails when a Codex round changed files outside the paths its task allows.
#
# codex exec --sandbox workspace-write lets Codex write anywhere in the
# worktree; this check (run by Claude after every writing round) is what keeps
# a round to the files its brief names.
#
# Usage (from the worktree root):
#   powershell -NoProfile -File tools\check_codex_scope.ps1 -Base <commit> -Allow "tests/codex/", "reports/red-team.md"
# An entry ending in "/" allows everything below that folder; any other entry
# allows exactly that file. Exit 0 = in scope, 1 = out of scope, 2 = usage/git error.
param(
    [Parameter(Mandatory = $true)][string]$Base,
    [Parameter(Mandatory = $true)][string[]]$Allow
)

$ErrorActionPreference = "Stop"
# Through `powershell -File`, "-Allow a,b" arrives as one string, not an array.
$Allow = @($Allow | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Get-Changed {
    # Committed since Base, staged, unstaged and untracked: Codex may leave any of them.
    $names = @()
    $names += git diff --name-only "$Base" --
    $names += git diff --name-only --cached --
    $names += git ls-files --others --exclude-standard
    if ($LASTEXITCODE -ne 0) { throw "git failed" }
    return $names | Where-Object { $_ } | ForEach-Object { $_ -replace "\\", "/" } | Sort-Object -Unique
}

function Test-Allowed([string]$Path) {
    foreach ($a in $Allow) {
        $rule = $a -replace "\\", "/"
        if ($rule.EndsWith("/")) {
            if ($Path.StartsWith($rule, [StringComparison]::Ordinal)) { return $true }
        } elseif ($Path -ceq $rule) {
            return $true
        }
    }
    return $false
}

try {
    git rev-parse --verify --quiet "$Base^{commit}" | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Output "unknown base commit: $Base"; exit 2 }
    $changed = @(Get-Changed)
} catch {
    Write-Output "error: $_"
    exit 2
}

$outside = @($changed | Where-Object { -not (Test-Allowed $_) })
foreach ($p in $changed) {
    $mark = if (Test-Allowed $p) { "ok " } else { "OUT" }
    Write-Output "$mark $p"
}
if ($outside.Count -gt 0) {
    Write-Output "SCOPE VIOLATION: $($outside.Count) file(s) outside the allowed paths"
    exit 1
}
Write-Output "in scope: $($changed.Count) file(s)"
exit 0
