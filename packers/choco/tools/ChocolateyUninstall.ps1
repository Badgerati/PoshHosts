# Determine which Program Files path to use
if (![string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
    $modulePath = Join-Path $env:ProgramFiles (Join-Path 'WindowsPowerShell' 'Modules')
}
else {
    $modulePath = Join-Path ${env:ProgramFiles(x86)} (Join-Path 'WindowsPowerShell' 'Modules')
}

# Delete PoshHosts module
$hostsModulePath = Join-Path $modulePath 'PoshHosts'
if (Test-Path $hostsModulePath)
{
    Write-Host 'Deleting PoshHosts module directory'
    Remove-Item -Path $hostsModulePath -Recurse -Force | Out-Null
    if (!$?) {
        throw "Failed to delete: $hostsModulePath"
    }
}