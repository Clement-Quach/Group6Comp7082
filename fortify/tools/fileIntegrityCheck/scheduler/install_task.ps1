<#
.SYNOPSIS
  Registers (or removes) a Windows Task Scheduler task that starts the integrity
  scheduler monitor every time you log on.

.EXAMPLE
  .\install_task.ps1                 # register, run at logon
  .\install_task.ps1 -StartNow       # register and start it immediately
  .\install_task.ps1 -Uninstall      # remove the task
#>
param(
    [switch]$Uninstall,
    [switch]$StartNow,
    [string]$TaskName = "FortifyIntegrityScheduler",
    [string]$Config   = (Join-Path $PSScriptRoot "schedule.json")
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed task '$TaskName'."
    } else {
        Write-Host "Task '$TaskName' does not exist."
    }
    return
}

# pythonw.exe = Python without a console window (the monitor logs to a file instead)
$pythonw = (Get-Command pythonw.exe -ErrorAction Stop).Source
$script  = Join-Path $PSScriptRoot "integrity_scheduler.py"
if (-not (Test-Path $script)) { throw "Not found: $script" }

$action    = New-ScheduledTaskAction -Execute $pythonw `
                 -Argument "`"$script`" --config `"$Config`"" `
                 -WorkingDirectory $PSScriptRoot
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet `
                 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                 -ExecutionTimeLimit ([TimeSpan]::Zero) `
                 -MultipleInstances IgnoreNew `
                 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Starts the Fortify file-integrity schedule monitor at logon." -Force | Out-Null

Write-Host "Registered task '$TaskName' (runs at logon)."
Write-Host "  python : $pythonw"
Write-Host "  script : $script"
Write-Host "  config : $Config"

if ($StartNow) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started."
}
