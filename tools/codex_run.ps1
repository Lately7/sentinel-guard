# Runs one Codex round non-interactively and saves its final answer.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\codex_run.ps1 `
#     -Brief docs\handoff\PROMPT_X.md -Out <answer.md> [-WorkDir <dir>] `
#     [-Sandbox read-only|workspace-write] [-Search] [-Image a.png,b.png] [-Prepend docs\research\briefs\common.md]
#
# Lessons baked in (2026-11-02):
# * PowerShell 5.1 pipes text to native programs as ASCII unless $OutputEncoding is UTF-8.
# * Call codex.cmd explicitly; never name a variable $args (PowerShell's automatic variable).
# * Model and effort are pinned here, not taken from ~/.codex/config.toml (owner: gpt-6-sol, high).
# * The log (all Codex output) goes next to -Out as <name>.log; tail it to watch progress.
param(
    [Parameter(Mandatory = $true)][string]$Brief,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$WorkDir = (Get-Location).Path,
    [ValidateSet("read-only", "workspace-write")][string]$Sandbox = "read-only",
    [switch]$Search,
    [string[]]$Image = @(),
    [string]$Prepend = "",
    [string]$Model = "gpt-6-sol",
    [string]$Effort = "high"
)

$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$Brief = (Resolve-Path $Brief).Path
if ($Prepend) { $Prepend = (Resolve-Path $Prepend).Path }
$Image = @($Image | ForEach-Object { $_ -split "," } | Where-Object { $_ } | ForEach-Object { (Resolve-Path $_).Path })
$Out = [System.IO.Path]::GetFullPath($Out)
$log = [System.IO.Path]::ChangeExtension($Out, ".log")
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null

$prompt = ""
if ($Prepend) { $prompt = (Get-Content -Raw -Encoding UTF8 $Prepend) + "`n`n" }
$prompt += Get-Content -Raw -Encoding UTF8 $Brief

$cargs = @()
if ($Search) { $cargs += "--search" }
$cargs += @("-m", $Model, "-c", "model_reasoning_effort=$Effort", "exec", "--sandbox", $Sandbox, "--skip-git-repo-check", "-C", $WorkDir)
foreach ($i in $Image) { $cargs += @("-i", $i) }
$cargs += @("-o", $Out, "-")

"===== $(Get-Date -Format s) codex $($cargs -join ' ')" | Out-File -Encoding utf8 -FilePath $log
$prompt | & codex.cmd @cargs 2>&1 | ForEach-Object { "$_" } | Out-File -Append -Encoding utf8 -FilePath $log
$code = $LASTEXITCODE
"===== $(Get-Date -Format s) done exit=$code" | Out-File -Append -Encoding utf8 -FilePath $log
exit $code
