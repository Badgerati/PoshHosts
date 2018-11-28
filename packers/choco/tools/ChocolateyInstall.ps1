$ErrorActionPreference = 'Stop'


# create the module directory, and copy files over
function Install-PoshHostsModule($path, $version)
{
    # Create PoshHosts module
    $path = Join-Path $path 'PoshHosts'
    if (![string]::IsNullOrWhiteSpace($version)) {
        $path = Join-Path $path $version
    }

    if (!(Test-Path $path))
    {
        Write-Host "Creating PoshHosts module directory: $($path)"
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        if (!$?) {
            throw "Failed to create: $path"
        }
    }

    # Copy contents to module
    Write-Host 'Copying PoshHosts to module path'

    try
    {
        Push-Location (Join-Path $env:ChocolateyPackageFolder 'src')

        Copy-Item -Path ./Tools.ps1 -Destination $path -Force | Out-Null
        Copy-Item -Path ./PoshHosts.psm1 -Destination $path -Force | Out-Null
        Copy-Item -Path ./PoshHosts.psd1 -Destination $path -Force | Out-Null
    }
    finally {
        Pop-Location
    }
}



# Determine which Program Files path to use
$progFiles = [string]$env:ProgramFiles
if (!(Test-Path $progFiles)) {
    $progFiles = [string]${env:ProgramFiles(x86)}
}

# Install PS Module
# Set the module path
$modulePath = Join-Path $progFiles (Join-Path 'WindowsPowerShell' 'Modules')

# Check to see if Modules path is in PSModulePaths
$psModules = $env:PSModulePath
if (!$psModules.Contains($modulePath))
{
    Write-Host 'Adding module path to PSModulePaths'
    $psModules += ";$modulePath"
    Install-ChocolateyEnvironmentVariable -VariableName 'PSModulePath' -VariableValue $psModules -VariableType Machine
    $env:PSModulePath = $psModules
}

# create the module
if ($PSVersionTable.PSVersion.Major -ge 5) {
    Install-PoshHostsModule $modulePath '$version$'
}
else {
    Install-PoshHostsModule $modulePath
}


# Install PS-Core Module
# Set the module path
$modulePath = Join-Path $progFiles (Join-Path 'PowerShell' 'Modules')

# create the module
Install-PoshHostsModule $modulePath '$version$'