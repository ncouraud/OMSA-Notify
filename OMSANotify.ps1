<#
.SYNOPSIS
This is a PowerShell Script to generate email alerts from Dell OpenManage Server Administrator Alerts
 
.DESCRIPTION
This Script Is used to send SMTP alerts from Servers running Dell Open Manage Server Administrator. It can automatically configure itself for most common OpenManage Alerts using the -Setup Parameter. It can also send test alerts using -Test.
 
.PARAMETER Setup 
Runs omconfig commands to set the script as action on alert generation.

.PARAMETER Test
Sends a test alert.

.PARAMETER eventType
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
   [string]$eventType,

   # Run the Setup Commands
   [switch]$Setup,
   
   # Send a Test Alert
   [switch]$Test
)

# Define the List of Alerts that we Respond to. Desired Alerts May be Added/Removed.  
$Alerts = @{}
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
$Alerts.Add("test",'Test Alert')

# Sends our Alert Mail
function sendMail($AlertType, $body) {
     #SMTP server name
     $smtpServer = "YOUR SMTP SERVER"

     #Creating a Mail object
     $msg = new-object Net.Mail.MailMessage

     #Creating SMTP server object
     $smtp = new-object Net.Mail.SmtpClient($smtpServer)

     #Email structure
     $msg.From = "$env:COMPUTERNAME@domain.com"
     $msg.ReplyTo = "No-Reply@domain.com"
     $msg.To.Add("ADMIN@domain.com")
     $msg.Subject = "Dell OMSA $AlertType Alert on $env:COMPUTERNAME"
     $msg.body = $body

     #Sending email
     $smtp.Send($msg)
 
}

# Kicks Off OM Alert Config Commands for all Warnings/Failures
Function Setup(){
    # Define our command String
    $ScriptPath = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Definition
    $command = "powershell "+$ScriptPath+" -eventType"

    # Set Up OpenManage Alert handlers
    SetOMAlert "powersupply" $command;
    SetOMAlert "powersupplywarn" $command;
    SetOMAlert "tempwarn" $command;
    SetOMAlert "tempfail" $command;
    SetOMAlert "fanwarn" $command;
    SetOMAlert "fanfail" $command;
    SetOMAlert "voltwarn" $command;
    SetOMAlert "voltfail" $command;
    SetOMAlert "Intrusion" $command;
    SetOMAlert "redundegrad" $command;
    SetOMAlert "redunlost" $command;
    SetOMAlert "memprefail" $command;
    SetOMAlert "memfail" $command;
    SetOMAlert "hardwarelogwarn" $command;
    SetOMAlert "hardwarelogfull" $command;
    SetOMAlert "processorwarn" $command;
    SetOMAlert "processorfail" $command;
    SetOMAlert "watchdogasr" $command;
    SetOMAlert "batterywarn" $command;
    SetOMAlert "batteryfail" $command;
    SetOMAlert "systempowerwarn" $command;
    SetOMAlert "systempowerfail" $command;
    SetOMAlert "storagesyswarn" $command;
    SetOMAlert "storagesysfail" $command;
    SetOMAlert "storagectrlwarn" $command;
    SetOMAlert "storagectrlfail" $command;
    SetOMAlert "pdiskwarn" $command;
    SetOMAlert "pdiskfail" $command;
    SetOMAlert "vdiskwarn" $command;
    SetOMAlert "vdiskfail" $command;
    SetOMAlert "enclosurewarn" $command;
    SetOMAlert "enclosurefail" $command;
    SetOMAlert "storagectrlbatterywarn" $command;
    SetOMAlert "storagectrlbatteryfail" $command;

    # Register Our Event Log Source
    if ([System.Diagnostics.EventLog]::SourceExists("OMSANotify") -eq $false) {
        [System.Diagnostics.EventLog]::CreateEventSource("OMSANotify", "System")
    }
}

# OMCONFIG Runner for individual Alert config
Function SetOMAlert($event, $cmdString){
    invoke-command -scriptblock {omconfig system alertaction event=$Event execappath="$cmdString $event"}
}

# Lets Generate A Test case Email, so we can be sure it works 
Function Test(){
    ProcessAlert "test";
    }

# Logs OMSA Event and Email in Windows Event Log
Function logEvent($event)
{
    $EventMsg = "OMSA Notify Processed Dell Open Manage Event $event"
    Write-EventLog -Logname System -Source OMSANotify -eventId 1 -entryType Warning -message $EventMsg
}

# Handles All Alert Processing. 
Function ProcessAlert($alert) {    
    $AlertMessageString = ""

    # Check if it's a known OMSA Alert
    If($Alerts.containsKey($alert)){
        $AlertMessageString = $Alerts.Get_Item($alert) + " was reported on $Env:COMPUTERNAME. Please log in ASAP and check OMSA for further details."
        }
    Else {
        "Unknown Alert - $alert was reported at $Date on $Env:COMPUTERNAME. Please log in ASAP and check OMSA for further details."
        }

    sendMail $alert $AlertMessageString;

    #Register our event in Windows Event Log. 
    logEvent $alert;
}


if($eventType) {
    ProcessAlert $event;
}
else {
    if($Setup) {
        Setup;
    }
    if($Test) {
        Test;
    }
}
