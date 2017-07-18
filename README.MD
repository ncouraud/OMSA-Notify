# OMSA-notify

## Synopsis

Dell OpenManager Server Administrator (OMSA) Notification Script.

This script updates your Dell OMSA Alert Management settings to call this script when alerts happen performing three actions; sending SMTP email of the alert, logging the alert to the Windows System event logs, and writes a local log file of alerts and errors.

## Contributors
* [Gabriel Martinez](https://github.com/GMartinez-Sisti)
* [Leith Tussing](https://github.com/brentil)
* [Nick Couraud](https://github.com/ncouraud)


## Installation

1. Copy OMSANotify.ps1 to a folder on the server (Example: C:\Scripts)
2. Update the setup variables in the script to match your environment
* $EmailSmtpServer    = "smtp.domain.local"       #Your SMTP server
* $EmailDomainSender  = "domain.local"            #The domain portion of your email address
* $EmailTo            = "recipient@domain.local"  #Email to send to
* $EmailReplyTo       = "no-reply@domain.local"   #Email to send as
3. From an Admin PowerShell run the script with the setup switch .\OMSANotify.ps1 -Setup
4. The script will update each alert type in OMSA to use the OMSANotify.ps1 script
5. Check in OMSA to verify the changes were made successfully OMSA -> Alert Management -> All Alerts -> Execute Application = Enabled + Script

## Tests

Testing the script setup.

1. From an Admin PowerShell run the script with the test switch .\OMSANotify.ps1 -Test
2. This will send a test email to the $EmailTo in the script

Testing OMSA integration.  You can alter a thermal probe to think it's outside of it's range to trigger and alert.

1. Login into OMSA and navigate to Shutdown -> Thermal Shutdown -> Thermal Protection Shutdown Severity = Disabled
* If it is enabled it is up to your discretion to disable it for testing.
2. Navigate to Main System Chassis -> Temperatures -> Choose a Probe -> Set to Values = Minimum Warning Threshold = Current Reading + 1
3. When you apply the setting you should instantly get an alert
4. While on the same page either choose Set to Default or Set to Values of your original value
5. If you altered the Thermal Protection Shutdown Severity set it back to your desired configuration

## Debugging

If the script errors during the email sending action it will write the error to a local fil named OMSANotify-error.log to help in debugging.

The Dell OMSA path must be in your system path or the calls to update OMSA will fail.

The current version of OMSA-Notify does not work with SMTP credentials.
