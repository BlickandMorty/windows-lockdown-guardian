[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$Apply,
    [string]$Acknowledgement
)

. (Join-Path $PSScriptRoot 'Common.ps1')

$config = Read-LockdownConfig -Path $ConfigPath
Assert-PolicyConsistency -Config $config
$domains = Get-PolicyDomains -Config $config
$root = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$config.installation.root))
$reportRoot = Join-Path $PSScriptRoot '..\reports'
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
$reportPath = Join-Path $reportRoot ("install-audit-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

$audit = [ordered]@{
    generatedAt = (Get-Date).ToString('o')
    computer = $env:COMPUTERNAME
    mode = [string]$config.mode
    applyRequested = [bool]$Apply
    administrator = Test-IsAdministrator
    installationRoot = $root
    blockedDomainCount = $domains.Count
    blockedExecutableCount = @($config.blockedExecutables).Count
    chromePolicy = [bool]$config.browserPolicy.chrome
    edgePolicy = [bool]$config.browserPolicy.edge
    optionalDnsEnabled = [bool]$config.optionalDns.enabled
    checks = @(
        'Configuration schema accepted',
        'Blocked and allowed domains do not collide',
        'Qobuz allow invariant preserved',
        'No API key is read or stored'
    )
}
Write-JsonReport -Path $reportPath -Value $audit

if (-not $Apply) {
    Write-Host "Audit complete. No system changes were made."
    Write-Host "Report: $reportPath"
    return
}

Assert-Administrator
$requiredPhrase = 'I UNDERSTAND THIS IS A PERMANENT RESTRICTION'
if ($config.mode -eq 'Permanent' -and $Acknowledgement -cne $requiredPhrase) {
    throw "Permanent mode requires -Acknowledgement '$requiredPhrase'"
}

if (-not $PSCmdlet.ShouldProcess($root, 'Install and apply lockdown guardian')) { return }

$baselineRoot = Join-Path $root 'Baseline'
$backupRoot = Join-Path $root ('Backups\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $baselineRoot, $backupRoot -Force | Out-Null

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
Copy-Item -LiteralPath $hostsPath -Destination (Join-Path $backupRoot 'hosts.before') -Force
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
    $safeName = $browser.Replace('\', '-')
    & reg.exe export "HKLM\SOFTWARE\Policies\$browser" (Join-Path $backupRoot "$safeName.before.reg") /y 2>$null | Out-Null
}

$sourceMap = [ordered]@{
    'Common.ps1' = (Join-Path $PSScriptRoot 'Common.ps1')
    'Guardian.ps1' = (Join-Path $PSScriptRoot 'Guardian.ps1')
    'Verify-Lockdown.ps1' = (Join-Path $PSScriptRoot 'Verify-Lockdown.ps1')
    'Export-DnsDenylist.ps1' = (Join-Path $PSScriptRoot 'Export-DnsDenylist.ps1')
    'policy.json' = (Resolve-Path -LiteralPath $ConfigPath).Path
    'PERMANENT-RULE.md' = (Join-Path $PSScriptRoot '..\docs\PERMANENT-RULE-TEMPLATE.md')
}

foreach ($entry in $sourceMap.GetEnumerator()) {
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $root $entry.Key) -Force
    Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $baselineRoot $entry.Key) -Force
}

$manifestEntries = foreach ($name in $sourceMap.Keys) {
    [ordered]@{
        target = $name
        baseline = "Baseline\$name"
        sha256 = Get-FileSha256 (Join-Path $baselineRoot $name)
    }
}
$manifest = [ordered]@{
    schemaVersion = 1
    createdAt = (Get-Date).ToString('o')
    entries = @($manifestEntries)
}
$manifestText = $manifest | ConvertTo-Json -Depth 8 -Compress

$secret = [byte[]]::new(64)
[Security.Cryptography.RandomNumberGenerator]::Fill($secret)
$protectedSecret = Protect-SecretForMachine -Secret $secret
[IO.File]::WriteAllBytes((Join-Path $root 'manifest.secret.protected'), $protectedSecret)
Write-AtomicUtf8 -Path (Join-Path $root 'manifest.json') -Content $manifestText
Write-AtomicUtf8 -Path (Join-Path $root 'manifest.hmac') -Content (Get-HmacHex -Key $secret -Text $manifestText)
[Array]::Clear($secret, 0, $secret.Length)

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Guardian.ps1') -Mode Once -Root $root
if ($LASTEXITCODE -ne 0) { throw "Initial guardian run failed with exit code $LASTEXITCODE" }

$taskPrefix = [string]$config.installation.taskPrefix
$minutes = [Math]::Max(15, [int]$config.installation.reapplyMinutes)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode Once -Root "{1}"' -f
    (Join-Path $root 'Guardian.ps1'), $root
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$hourlyTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
    -RepetitionInterval (New-TimeSpan -Minutes $minutes) -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName "$taskPrefix Startup" -Action $action -Trigger $startupTrigger -Principal $principal -Settings $settings -Force | Out-Null
Register-ScheduledTask -TaskName "$taskPrefix Recurring" -Action $action -Trigger $hourlyTrigger -Principal $principal -Settings $settings -Force | Out-Null

Set-SystemManagedAcl -Path $root

$audit.applied = $true
$audit.installedAt = (Get-Date).ToString('o')
$audit.tasks = @("$taskPrefix Startup", "$taskPrefix Recurring")
Write-JsonReport -Path $reportPath -Value $audit
Write-Host "Lockdown guardian installed and applied."
Write-Host "Verification: powershell -File `"$root\Verify-Lockdown.ps1`" -Root `"$root`""
Write-Host "Report: $reportPath"
