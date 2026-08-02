Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw 'This operation requires an elevated PowerShell session.'
    }
}

function Read-LockdownConfig {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $config = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($config.schemaVersion -ne 1) { throw "Unsupported schemaVersion: $($config.schemaVersion)" }
    if ($config.mode -notin @('Permanent', 'Managed')) { throw 'mode must be Permanent or Managed.' }
    if (-not $config.installation.root) { throw 'installation.root is required.' }
    return $config
}

function Get-NormalizedDomains {
    param([object[]]$Values)

    @($Values | ForEach-Object {
        $value = ([string]$_).Trim().ToLowerInvariant()
        $value = $value -replace '^https?://', ''
        $value = $value.Split('/')[0].TrimEnd('.')
        if ($value.StartsWith('*.')) { $value = $value.Substring(2) }
        if ($value -and $value -match '^[a-z0-9.-]+$') { $value }
    } | Sort-Object -Unique)
}

function Test-DomainRelationship {
    param([string]$Left, [string]$Right)

    return $Left -eq $Right -or $Left.EndsWith(".$Right") -or $Right.EndsWith(".$Left")
}

function Assert-PolicyConsistency {
    param([Parameter(Mandatory)]$Config)

    $blocked = Get-NormalizedDomains @($Config.blockedDomains) + @($Config.adultDomains)
    $blocked = @($blocked | Sort-Object -Unique)
    $allowed = Get-NormalizedDomains @($Config.allowDomains)
    $conflicts = foreach ($block in $blocked) {
        foreach ($allow in $allowed) {
            if (Test-DomainRelationship $block $allow) { "$block <-> $allow" }
        }
    }
    if ($conflicts) {
        throw "Blocked/allowed domain collision(s): $($conflicts -join ', ')"
    }
    if ($blocked | Where-Object { Test-DomainRelationship $_ 'qobuz.com' }) {
        throw 'Qobuz is a protected compatibility invariant and cannot appear in the block list.'
    }
    if ($Config.mode -eq 'Permanent' -and $blocked.Count -eq 0) {
        throw 'A Permanent policy must contain at least one explicit blocked domain.'
    }
}

function Write-AtomicUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temporary = Join-Path $parent ('.tmp-' + [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-HmacHex {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][string]$Text
    )

    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    try {
        ([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant()
    }
    finally { $hmac.Dispose() }
}

function Protect-SecretForMachine {
    param([Parameter(Mandatory)][byte[]]$Secret)
    [Security.Cryptography.ProtectedData]::Protect(
        $Secret,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
}

function Unprotect-MachineSecret {
    param([Parameter(Mandatory)][byte[]]$ProtectedSecret)
    [Security.Cryptography.ProtectedData]::Unprotect(
        $ProtectedSecret,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
}

function Set-SystemManagedAcl {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Cannot protect missing path: $Path" }
    & icacls.exe $Path /setowner '*S-1-5-18' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set SYSTEM owner on $Path" }
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(RX)' '*S-1-5-32-545:(OI)(CI)(RX)' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set protected ACL on $Path" }
}

function Write-JsonReport {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    Write-AtomicUtf8 -Path $Path -Content ($Value | ConvertTo-Json -Depth 12)
}

function Get-PolicyDomains {
    param([Parameter(Mandatory)]$Config)
    @(Get-NormalizedDomains (@($Config.blockedDomains) + @($Config.adultDomains)) | Sort-Object -Unique)
}

function Get-BrowserUrlPatterns {
    param([Parameter(Mandatory)][string[]]$Domains)
    @($Domains | ForEach-Object { "*://$_/*"; "*://*.$_/*" } | Sort-Object -Unique)
}

function Get-InstalledRoot {
    param([string]$ExplicitRoot)
    if ($ExplicitRoot) { return [IO.Path]::GetFullPath($ExplicitRoot) }
    return [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
}

