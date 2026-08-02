$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scripts = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.ps1' -File
$failed = $false
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) {
        $failed = $true
        Write-Error "$($script.Name): $($errors -join '; ')"
    }
}
$config = Get-Content -LiteralPath (Join-Path $root 'config\policy.example.json') -Raw | ConvertFrom-Json
if ($config.allowDomains -notcontains 'qobuz.com') { throw 'Qobuz allow invariant missing.' }
if (@($config.blockedDomains | Where-Object { $_ -match '(?i)qobuz' }).Count) { throw 'Qobuz appears in block list.' }
if ($failed) { exit 1 }
Write-Host "Static checks passed for $($scripts.Count) scripts."

