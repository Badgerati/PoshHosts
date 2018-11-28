function Remove-PoshHostsModule($path)
{
    $path = Join-Path $path 'PoshHosts'
    if (Test-Path $path)
    {
        Write-Host "Deleting PoshHosts module directory: $($path)"
        Remove-Item -Path $path -Recurse -Force | Out-Null
        if (!$?) {
            throw "Failed to delete: $path"
        }
    }
}


# Determine which Program Files path to use
$progFiles = [string]$env:ProgramFiles
if (!(Test-Path $progFiles)) {
    $progFiles = [string]${env:ProgramFiles(x86)}
}

# Remove PS Module
# Set the module path
$modulePath = Join-Path $progFiles (Join-Path 'WindowsPowerShell' 'Modules')

# Delete PoshHosts module
Remove-PoshHostsModule $modulePath

# Remove PS-Core Module
# Set the module path
$modulePath = Join-Path $progFiles (Join-Path 'PowerShell' 'Modules')

# Delete PoshHosts module
Remove-PoshHostsModule $modulePath