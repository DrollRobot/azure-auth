<#
.SYNOPSIS
    Installs or removes a scheduled task that empties the azure-auth testing token cache folder
    at logon.

.DESCRIPTION
    The live tests keep an encrypted token cache in the per-user cache folder, so that one
    interactive sign-in serves later unattended runs. On a machine used only for testing, this
    task empties that folder every time the user logs on, so a cached sign-in does not outlive
    the session it was made in.

    The task runs as the current user and needs no administrator rights. It deletes everything
    in %LOCALAPPDATA%\azure-auth\Cache: the package's default cache, the live-test cache and
    their lock files. A cache a caller placed elsewhere with cache_path= is not touched.

    Task Scheduler has no logoff trigger, so only logon is covered. Disconnecting a Remote
    Desktop session is not a logoff, so it only runs after real logoff + logon or restart +
    logon.

.PARAMETER Uninstall
    Remove the task instead of installing it.

.EXAMPLE
    .\scripts\Install-TokenCacheCleanupTask.ps1

.EXAMPLE
    .\scripts\Install-TokenCacheCleanupTask.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch] $Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'azure-auth clear token cache at logon'
$TaskPath = '\'

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    }
    else {
        Write-Host "No scheduled task named '$TaskName'; nothing to remove."
    }
    return
}

# Must match azure_auth.auth.cache.default_cache_path(), which is platformdirs' per-user cache
# folder for the application name "azure-auth".
if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not set, so the cache folder cannot be located.'
}
$CacheDir = Join-Path $env:LOCALAPPDATA 'azure-auth\Cache'
# A relative path here would make the task delete from whatever directory it starts in.
if (-not [System.IO.Path]::IsPathRooted($CacheDir)) {
    throw "Refusing to install: the cache folder '$CacheDir' is not an absolute path."
}

# The path is fixed into the task now rather than read from the environment when it runs, so
# what the task deletes is exactly what this script printed. Single quotes are doubled for the
# single-quoted PowerShell string it goes into.
$Literal = $CacheDir.Replace("'", "''")
$Command = "if (Test-Path -LiteralPath '$Literal') { Get-ChildItem -LiteralPath '$Literal' -Force" +
    " | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }"

$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$Command`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings -Force `
    -Description "Empties $CacheDir at each logon of $User. Installed by azure-auth's scripts/Install-TokenCacheCleanupTask.ps1." |
    Out-Null

Write-Host "Installed scheduled task '$TaskName'."
Write-Host "At each logon of $User it empties: $CacheDir"
