param (
    [string]
    $Version = ''
)

<#
# Helper Functions
#>

function Test-IsWindows
{
    $v = $PSVersionTable
    return ($v.Platform -ilike '*win*' -or ($null -eq $v.Platform -and $v.PSEdition -ieq 'desktop'))
}

function Test-Command($cmd)
{
    $path = (Get-Command $cmd -ErrorAction Ignore)
    return (![string]::IsNullOrWhiteSpace($path))
}

function Invoke-Install($name, $version)
{
    if (Test-Command 'choco') {
        choco install $name --version $version -y
    }
}


<#
# Helper Tasks
#>

# Synopsis: Stamps the version onto the Module
task StampVersion {
    (Get-Content ./src/PoshHosts.psd1) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./src/PoshHosts.psd1
    (Get-Content ./packers/choco/poshhosts.nuspec) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./packers/choco/poshhosts.nuspec
    (Get-Content ./packers/choco/tools/ChocolateyInstall.ps1) | ForEach-Object { $_ -replace '\$version\$', $Version } | Set-Content ./packers/choco/tools/ChocolateyInstall.ps1
}

# Synopsis: Generating a Checksum of the Zip
task PrintChecksum {
    $Script:Checksum = (checksum -t sha256 $Version-Binaries.zip)
    Write-Host "Checksum: $($Checksum)"
}


<#
# Dependencies
#>

# Synopsis: Installs Chocolatey
task ChocoDeps -If (Test-IsWindows) {
    if (!(Test-Command 'choco')) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}

# Synopsis: Install dependencies for packaging
task PackDeps -If (Test-IsWindows) ChocoDeps, {
    if (!(Test-Command 'checksum')) {
        Invoke-Install 'checksum' '0.2.0'
    }

    if (!(Test-Command '7z')) {
        Invoke-Install '7zip' '18.5.0.20180730'
    }
}

# Synopsis: Install dependencies for running tests
task TestDeps {
    if (((Get-Module -ListAvailable Pester) | Where-Object { $_.Version -ieq '4.4.2' }) -eq $null) {
        Write-Host 'Installing Pester'
        Install-Module -Name Pester -Scope CurrentUser -RequiredVersion '4.4.2' -Force -SkipPublisherCheck
    }
}


<#
# Packaging
#>

# Synopsis: Creates a Zip of the Module
task 7Zip -If (Test-IsWindows) PackDeps, StampVersion, {
    exec { & 7z -tzip a $Version-Binaries.zip ./src/* }
}, PrintChecksum

# Synopsis: Creates a Chocolately package of the Module
task ChocoPack -If (Test-IsWindows) PackDeps, StampVersion, {
    exec { choco pack ./packers/choco/poshhosts.nuspec }
}

# Synopsis: Package up the Module
task Pack -If (Test-IsWindows) 7Zip, ChocoPack


<#
# Testing
#>

# Synopsis: Run the tests
task Test TestDeps, {
    $p = (Get-Command Invoke-Pester)
    if ($null -eq $p -or $p.Version -ine '4.4.2') {
        Import-Module Pester -Force -RequiredVersion '4.4.2'
    }

    $Script:TestResultFile = "$($pwd)/TestResults.xml"
    $Script:TestStatus = Invoke-Pester './tests' -OutputFormat NUnitXml -OutputFile $TestResultFile -PassThru
}, PushAppVeyorTests, CheckFailedTests

# Synopsis: Check if any of the tests failed
task CheckFailedTests {
    if ($TestStatus.FailedCount -gt 0) {
        throw "$($TestStatus.FailedCount) tests failed"
    }
}

# Synopsis: If AppVeyor, push result artifacts
task PushAppVeyorTests -If (![string]::IsNullOrWhiteSpace($env:APPVEYOR_JOB_ID)) {
    $url = "https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)"
    (New-Object 'System.Net.WebClient').UploadFile($url, $TestResultFile)
    Push-AppveyorArtifact $TestResultFile
}