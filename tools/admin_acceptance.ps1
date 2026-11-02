<# Owner-only A3 acceptance driver. The disposable M7 fixture supplies measured JSON per stage. #>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [string]$FixtureServiceName,
    [string]$FixturePipeName,
    [string]$FixtureStateRoot,
    [string]$FixtureVersionRoot,
    [string]$FixtureRunner
)

$ErrorActionPreference = 'Stop'
$stages = @('preflight', 'service_config', 'storage_pipe', 'worker',
            'usn_sources', 'observation_download', 'action_recovery', 'lifecycle')
if ($WhatIf) {
    foreach ($stage in $stages) { Write-Output "PLAN $stage" }
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'Cần phiên đăng nhập tương tác với quyền quản trị.'
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SentinelAcceptanceToken {
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr t);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr t, int c, IntPtr b, uint n, out uint need);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
}
'@
$token = [IntPtr]::Zero
if (-not [SentinelAcceptanceToken]::OpenProcessToken([SentinelAcceptanceToken]::GetCurrentProcess(), 0x8, [ref]$token)) {
    throw 'Không thể đọc mã thông báo tiến trình.'
}
try {
    $elev = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    $label = [Runtime.InteropServices.Marshal]::AllocHGlobal(256)
    try {
        $need = [uint32]0
        if (-not [SentinelAcceptanceToken]::GetTokenInformation($token, 20, $elev, 4, [ref]$need)) {
            throw 'Không thể kiểm tra quyền nâng cao.'
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($elev) -ne 1) {
            throw 'Cần chạy bằng quyền quản trị nâng cao.'
        }
        if (-not [SentinelAcceptanceToken]::GetTokenInformation($token, 25, $label, 256, [ref]$need)) {
            throw 'Không thể kiểm tra mức toàn vẹn.'
        }
        $sidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($label)
        $count = [Runtime.InteropServices.Marshal]::ReadByte($sidPtr, 1)
        $rid = [Runtime.InteropServices.Marshal]::ReadInt32($sidPtr, 8 + 4 * ($count - 1))
        if ($rid -lt 0x3000) { throw 'Cần mã thông báo toàn vẹn cao.' }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($elev)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($label)
    }
} finally {
    [SentinelAcceptanceToken]::CloseHandle($token) | Out-Null
}

if ($FixtureServiceName -notmatch '^SentinelGuardTest-[0-9a-f]{16,32}$' -or
    $FixturePipeName -notmatch '^\\\\\.\\pipe\\SentinelGuardTest-[0-9a-f]{16,32}$') {
    throw 'Cần tên dịch vụ và pipe thử nghiệm duy nhất.'
}
foreach ($path in @($FixtureStateRoot, $FixtureVersionRoot, $FixtureRunner)) {
    if (-not [IO.Path]::IsPathFullyQualified($path)) { throw 'Cần đường dẫn thử nghiệm tuyệt đối.' }
}
$stateParent = [IO.Path]::GetFullPath([Environment]::GetFolderPath('CommonApplicationData')).TrimEnd('\') + '\'
$codeParent = [IO.Path]::GetFullPath([Environment]::GetFolderPath('ProgramFiles')).TrimEnd('\') + '\'
$state = [IO.Path]::GetFullPath($FixtureStateRoot)
$code = [IO.Path]::GetFullPath($FixtureVersionRoot)
if (-not $state.StartsWith($stateParent, [StringComparison]::OrdinalIgnoreCase) -or
    -not $code.StartsWith($codeParent, [StringComparison]::OrdinalIgnoreCase) -or
    $state -notmatch 'SentinelGuardTest-[0-9a-f]{16,32}' -or
    $code -notmatch 'SentinelGuardTest-[0-9a-f]{16,32}') {
    throw 'Gốc thử nghiệm phải tách biệt trong thư mục được bảo vệ.'
}
if (-not (Test-Path -LiteralPath $FixtureRunner -PathType Leaf)) {
    throw 'Thiếu bộ kiểm thử độc lập được bảo vệ.'
}

$required = @{
    preflight = @('token', 'runtime_hashes', 'sys_path', 'no_reparse', 'disposable_fixture', 'negative_import')
    service_config = @('sc_qc', 'sid_type', 'privileges', 'failure_actions', 'failure_flag', 'sddl', 'running', 'medium_stop_denied')
    storage_pipe = @('state_acl', 'pipe_acl', 'local_only', 'status', 'own_scan', 'store_denied', 'malformed_denied', 'mutation_denied')
    worker = @('restricted_sid', 'low_integrity', 'job_limits', 'protected_imports', 'marker_scan', 'writes_denied', 'crash_typed')
    usn_sources = @('cursor_restart', 'invalid_cursor_explicit', 'cross_user_source')
    observation_download = @('process_counters', 'interval_gap', 'completed_file', 'hint_no_action')
    action_recovery = @('prepared_journal', 'barrier', 'no_double_action', 'identity_rechecked')
    lifecycle = @('defender_read_only', 'crash_recovery', 'clean_stop', 'lease_handoff', 'uninstall', 'retained_state')
}
$installedHere = $false
try {
    foreach ($stage in $stages) {
        $argsForFixture = @('--stage', $stage, '--service', $FixtureServiceName,
                            '--pipe', $FixturePipeName, '--state', $state, '--version', $code)
        $raw = & $FixtureRunner @argsForFixture
        if ($LASTEXITCODE -ne 0) { throw "Thử nghiệm $stage thất bại." }
        $evidence = ($raw | Out-String) | ConvertFrom-Json -ErrorAction Stop
        if ($evidence.stage -ne $stage -or $evidence.disposable_service -ne $FixtureServiceName) {
            throw "Chứng cứ $stage không khớp đối tượng thử nghiệm."
        }
        foreach ($key in $required[$stage]) {
            if ($evidence.$key -ne $true) { throw "Thiếu chứng cứ $stage/$key." }
        }
        if ($stage -eq 'service_config') { $installedHere = $true }
        if ($stage -eq 'storage_pipe' -and $evidence.remote_os -ne $true) {
            Write-Output 'SKIP remote_os'
            throw 'Cần máy từ xa để xác nhận từ chối kết nối mạng.'
        }
        Write-Output "PASS $stage"
    }
} finally {
    if ($installedHere) {
        & sc.exe stop $FixtureServiceName | Out-Null
        & sc.exe delete $FixtureServiceName | Out-Null
    }
    Write-Output "STATE_RETAINED $state"
}
