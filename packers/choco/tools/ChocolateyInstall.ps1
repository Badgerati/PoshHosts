$ErrorActionPreference = 'Stop'

# Install Module
# Determine which Program Files path to use
if (![string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
    $modulePath = Join-Path $env:ProgramFiles (Join-Path 'WindowsPowerShell' 'Modules')
}
else {
    $modulePath = Join-Path ${env:ProgramFiles(x86)} (Join-Path 'WindowsPowerShell' 'Modules')
}

# Check to see if we need to create the Modules path
if (!(Test-Path $modulePath))
{
    Write-Host "Creating path: $modulePath"
    New-Item -ItemType Directory -Path $modulePath -Force | Out-Null
    if (!$?) {
        throw "Failed to create: $modulePath"
    }
}

# Check to see if Modules path is in PSModulePaths
$psModules = $env:PSModulePath
if (!$psModules.Contains($modulePath))
{
    Write-Host 'Adding module path to PSModulePaths'
    $psModules += ";$modulePath"
    Install-ChocolateyEnvironmentVariable -VariableName 'PSModulePath' -VariableValue $psModules -VariableType Machine
    $env:PSModulePath = $psModules
}

# Create PoshHosts module
$hostsModulePath = Join-Path $modulePath 'PoshHosts'
if (!(Test-Path $hostsModulePath))
{
    Write-Host 'Creating PoshHosts module directory'
    New-Item -ItemType Directory -Path $hostsModulePath -Force | Out-Null
    if (!$?) {
        throw "Failed to create: $hostsModulePath"
    }
}

# Copy contents to module
Write-Host 'Copying PoshHosts to module path'

try
{
    Push-Location (Join-Path $env:ChocolateyPackageFolder 'src')

    New-Item -ItemType Directory -Path (Join-Path $hostsModulePath 'Tools') -Force | Out-Null
    Copy-Item -Path ./Tools.ps1 -Destination $hostsModulePath -Force | Out-Null
    Copy-Item -Path ./PoshHosts.psm1 -Destination $hostsModulePath -Force | Out-Null
    Copy-Item -Path ./PoshHosts.psd1 -Destination $hostsModulePath -Force | Out-Null
}
finally {
    Pop-Location
}