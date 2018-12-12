# Hosts

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/Badgerati/PoshHosts/master/LICENSE.txt)
[![AppVeyor](https://img.shields.io/appveyor/ci/Badgerati/PoshHosts/master.svg?label=AppVeyor)](https://ci.appveyor.com/project/Badgerati/poshhosts/branch/master)
[![Travis CI](https://img.shields.io/travis/Badgerati/PoshHosts/master.svg?label=Travis%20CI)](https://travis-ci.org/Badgerati/PoshHosts)

[![Chocolatey](https://img.shields.io/chocolatey/dt/poshhosts.svg?label=Chocolatey&colorB=a1301c)](https://chocolatey.org/packages/poshhosts)
[![PowerShell](https://img.shields.io/powershellgallery/dt/poshhosts.svg?label=PowerShell&colorB=085298)](https://www.powershellgallery.com/packages/PoshHosts)

Module that introduces a new `hosts` command on your terminal, that allows you to control the hosts file from the command line - on Windows, Linux and MacOS.

The `hosts` commands allows you to add/remove entries; as well enable/disable them. It also supports profiles, so you can have a developer hosts file in your repo and import/merge it for developers.

The `hosts` command also lets you test entries by pinging them, either using the normal ping or by passing specific ports.

## Features

* Control the hosts file from the command line
* Support for host profiles, useful for local environments
* Test entries in a hosts file by pinging them - even with specific ports
* Display a diff between two host files
* Support for environment sections in host files
* Support for RDPing onto servers via host entries
* Ability to open the hosts file from CLI (notepad on Windows, Vi on Unix)

## Install

You can install PoshHosts from either Chocolatey or the PowerShell Gallery:

```powershell
# chocolatey
choco install poshhosts

# powershell gallery
Install-Module -Name PoshHosts
```

## Commands

Format: `hosts <command> [<v1>] [<v2>] [-p <hosts-path>] [-e <environment>] [-c <pscredentials>]`

* `-v1` and `-v2` supply the main data to commands: such as IP addresses, host names, paths and ports.
* `-p` allows you to override the default main hosts file path with a custom one.
* `-e` allows you to control specific environments, such as add an entry or remove all entries for an environment.
* `-c` allows you to specify credentials - is only used for `rdp` currently

> Actions that alter data in the hosts file will always create a `.bak` first; so if the command fails, then the hosts are restored from this `.bak`. If you mess-up and need to restore, the `.bak` is always left in place, calling `hosts restore` will solve your problems!

```powershell
# adds new entries
hosts add 127.0.0.2 dev.test.local
hosts add 192.168.0.1 build.office, build
hosts add 10.10.1.3 site.test -e staging

# sets entries, removing any previous settings
hosts set 127.0.0.3 qa.test.local
hosts set 10.10.1.2 private.software.live, private.website.live

# removes entries
hosts remove 127.0.0.2
hosts remove *.office
hosts remove 192.168.*, *.local
hosts remove 192.* -e office
hosts remove -e dev

# disables an entry (by commenting it out)
hosts disable dev.test.local
hosts disable 192.168.*, *.local
hosts disable *.local -e dev

# enables an entry (by uncommenting it out)
hosts enable dev.test.local
hosts enable 192.168.*, *.local
hosts enable *.local -e dev

# completely clears all entries
hosts clear

# displays the path to the hosts file
hosts path

# lists entries
hosts list
hosts list *.office
hosts list 192.168.*, *.local
hosts list -e live

# tests entries by pinging - can also use specific ports
hosts test
hosts test * 443
hosts test dev.test.local 80, 443
hosts test * -e dev
hosts test * 80, 443 -e live

# rdp onto entries
hosts rdp 10.21.*
hosts rdp -e test
hosts rdp qa.test -c (Get-Credential)

# open entries in default browser (default protocol is https)
hosts browse *.local
hosts browse qa.test http
hosts browse -e live

# creates a backup of the hosts file - can also specify custom file path
hosts backup
hosts backup ./dev.hosts.bak

# restores the hosts file from the backup - can also specify custom file path
hosts restore
hosts restore ./dev.hosts.bak

# exports the hosts file to the specified path - useful for profiles
hosts export ./dev.profile.hosts
hosts export ./profile.hosts *.local
hosts export ./qa.profile.hosts -e qa

# imports a hosts profile, replacing the main hosts file
hosts import ./dev.profile.hosts
hosts import ./profile.hosts *.local
hosts import ./qa.profile.hosts -e qa

# merges the hosts file with host profiles (profile has precendence)
hosts merge ./dev.profile.hosts
hosts merge ./dev.profile.hosts, ./qa.profile.hosts

# displays the diff of the hosts file to a hosts profile
hosts diff ./dev.profile.hosts

# displays the contents of the hosts file on the command line
hosts show

# open the hosts file for editting
hosts open
```