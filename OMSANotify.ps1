<#
.SYNOPSIS
This is a PowerShell Script to generate email alerts from Dell OpenManage Server Administrator Alerts

.DESCRIPTION
This Script Is used to send SMTP alerts from Servers running Dell Open Manage Server Administrator. It can automatically configure itself for most common OpenManage Alerts using the -Setup Parameter. It can also send test alerts using -Test.

.PARAMETER Setup
Runs omconfig commands to set the script as action on alert generation.

.PARAMETER Test
Sends a test alert.

.PARAMETER EventType
The Event Class to generate an Alert for.

.EXAMPLE
./OMSANotify.ps1 -Test


.LINK
https://bitbucket.org/ncouraud/omsa-notify
#>

# Setup Our Parameters
[CmdletBinding()]
Param(
   # The Event Type that we need to respond to.
   [Parameter(Mandatory=$False,Position=1)]
   [string]$EventType,

   # Run the Setup Commands
   [switch]$Setup,

   # Send a Test Alert
   [switch]$Test
)

# Setup our Variables

$EmailSmtpServer = "smtp.domain.local"
$EmailDomainSender = "domain.local"
$EmailTo = "recipient@domain.local"
$EmailReplyTo = "no-reply@domain.local"

# Define the List of Alerts that we Respond to. Desired Alerts May be Added/Removed.
$Alerts = @{}
$Alerts.Add("test",'Test Alert')
$Alerts.Add("powersupply",'Power Supply Failure')
$Alerts.Add("powersupplywarn",'Power Supply Warning')
$Alerts.Add("tempwarn",'Temperature Warning')
$Alerts.Add("tempfail",'Temperature Failure')
$Alerts.Add("fanwarn",'Fan Speed Warning')
$Alerts.Add("fanfail",'Fan Speed Failure')
$Alerts.Add("voltwarn",'Voltage warning')
$Alerts.Add("voltfail",'Voltage Failure')
$Alerts.Add("Intrusion",'Chassis Intrusion')
$Alerts.Add("redundegrad",'Redundancy Degraded')
$Alerts.Add("redunlost",'Redundancy Lost')
$Alerts.Add("memprefail",'Memory Pre-Failure')
$Alerts.Add("memfail",'Memory Failure')
$Alerts.Add("hardwarelogwarn",'Hardware Log Warning')
$Alerts.Add("hardwarelogfull",'Hardware Log Full')
$Alerts.Add("processorwarn",'Processor Warning')
$Alerts.Add("processorfail",'Processor Failure')
$Alerts.Add("watchdogasr",'Watchdog ASR')
$Alerts.Add("batterywarn",'Battery Warning')
$Alerts.Add("batteryfail",'Battery Failure')
$Alerts.Add("systempowerwarn",'System Power Warning')
$Alerts.Add("systempowerfail",'System Power Failure')
$Alerts.Add("storagesyswarn",'Storage System Warning')
$Alerts.Add("storagesysfail",'Storage System Failure')
$Alerts.Add("storagectrlwarn",'Storage Controller Warning')
$Alerts.Add("storagectrlfail",'Storage Controller Failure')
$Alerts.Add("pdiskwarn",'Physical Disk Warning')
$Alerts.Add("pdiskfail",'Physical Disk Failure')
$Alerts.Add("vdiskwarn",'Virtual Disk Warning')
$Alerts.Add("vdiskfail",'Virtual Disk Failure')
$Alerts.Add("enclosurewarn",'Enclosure Warning')
$Alerts.Add("enclosurefail",'Enclosure Failure')
$Alerts.Add("storagectrlbatterywarn",'Storage Controller Battery Warning')
$Alerts.Add("storagectrlbatteryfail",'Storage Controller Battery Failure')

# Sends our Alert Mail
Function sendMail($AlertType, $Body) {

     #Creating a Mail object
     $Msg = new-object Net.Mail.MailMessage

     #Creating SMTP server object
     $Smtp = new-object Net.Mail.SmtpClient($EmailSmtpServer)

     #Email structure
     $Msg.From = "$env:COMPUTERNAME@$EmailDomainSender"
     $Msg.ReplyTo = $EmailReplyTo
     $Msg.To.Add($EmailTo)
     $Msg.Subject = "Dell OMSA - $AlertType Alert on $($Env:COMPUTERNAME)"
     $Msg.body = $Body

     #Sending email
     $Smtp.Send($Msg)

}

# Kicks Off OM Alert Config Commands for all Warnings/Failures
Function Setup() {
    # Define our command String
    $ScriptPath = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Definition
    $command = "powershell "+$ScriptPath+" -EventType"

    # Set Up OpenManage Alert handlers
    Foreach ($Alert in $Alerts.Keys) {
        If ( $Alert -NotLike "test" ) {
            SetOMAlert $Alert $command
        }
    }

    # Register Our Event Log Source
    If ([System.Diagnostics.EventLog]::SourceExists("OMSANotify") -eq $false) {
        [System.Diagnostics.EventLog]::CreateEventSource("OMSANotify", "System")
    }
}

# OMCONFIG Runner for individual Alert config
Function SetOMAlert($Event, $cmdString) {
    Invoke-Command -Scriptblock {omconfig system alertaction event=$Event execappath="$cmdString $Event"}
}

# Lets Generate A Test case Email, so we can be sure it works
Function Test() {
    ProcessAlert "test"
    }

# Logs OMSA Event and Email in Windows Event Log
Function logEvent($Event) {
    Write-EventLog -Logname System -Source OMSANotify -EventId 1 -EntryType Warning -Message $Event
}

# Handles All Alert Processing.
Function ProcessAlert($Alert) {
    $AlertMessageString = ""

    # Check if it's a known OMSA Alert
    If ( $Alerts.containsKey($Alert) ) {
        $AlertProcessed = "$($Alerts.Get_Item($Alert))"
    }
    Else {
        $AlertProcessed = "Unknown Alert - $Alert"
    }

    $AlertMessageString = "$AlertProcessed was reported at $Date on $($Env:COMPUTERNAME). Check OMSA for further details - https://$($Env:COMPUTERNAME):1311"
    sendMail $AlertProcessed $AlertMessageString
    logEvent $AlertMessageString
}

If ($EventType) {
    ProcessAlert $EventType
}
Else {
    If ($Setup) {
        Setup
    }
    If ($Test) {
        Test
    }
}
