<#

.SYNOPSIS
    Registers a scheduled task that runs Update-DcLdapsCertificate.ps1 whenever a new server authentication certificate is installed in the local machine certificate store on a domain controller deployed behind a load balancer for highly available LDAP over TLS (LDAPS).

.DESCRIPTION
    This script is intended for domain controllers deployed behind a load balancer to provide a highly available LDAPS service. Clients connect to a single LDAPS service name (for example, ldaps.lab.richardhicks.net) that resolves to the load balancer's virtual IP address, so every domain controller in the pool must serve a certificate that includes that name in the subject alternative name. Run this script on each domain controller in the pool.

    Certificate autoenrollment places a new or renewed LDAPS certificate in the local machine personal store, but Active Directory Domain Services (AD DS) does not use it until it is copied to the NTDS service certificate store. This script registers a scheduled task that runs Update-DcLdapsCertificate.ps1 in response to the certificate installation event, so the NTDS store is updated as soon as autoenrollment completes.

    The task is triggered only by events. It has no time-based trigger and never runs on a schedule. The trigger subscribes to the Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational log and fires on event ID 1006 (a new certificate has been installed) or event ID 1001 (a certificate has been replaced) where the certificate was installed in the machine context and includes the Server Authentication enhanced key usage. Certificates installed in a user context, and machine certificates without the Server Authentication EKU, do not trigger the task. A one minute delay is applied before the task starts so autoenrollment has finished writing the certificate and private key.

    The following actions are performed:

    - Verifies that Update-DcLdapsCertificate.ps1 exists at the specified path.
    - Ensures the Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational event log is enabled. This log is the source of the trigger event and is enabled by default, but is re-enabled if it has been turned off.
    - Sets the AEEventLogLevel registry value to 0 so autoenrollment writes detailed events to the Application log. This does not affect the trigger but provides a record of each autoenrollment pass for troubleshooting.
    - Registers the scheduled task to run as SYSTEM with highest privileges, using Windows PowerShell to execute Update-DcLdapsCertificate.ps1 with the specified template OID and LDAPS service name. Update-DcLdapsCertificate.ps1 writes its own transcript log with verbose output always enabled, so no additional logging parameters are passed. An existing task with the same name is replaced.

    Because certificate installation events are also raised when a certificate is installed manually, the task can run in response to a manual installation of a qualifying certificate. Update-DcLdapsCertificate.ps1 is idempotent and only binds a certificate issued from the specified template that includes the LDAPS service name, so this has no effect unless the installed certificate qualifies.

    All changes support -WhatIf and -Confirm. This script requires Administrator privileges and Windows PowerShell 5.1.

.PARAMETER TemplateOid
    The object identifier (OID) of the certificate template used to issue the LDAPS certificate. This value is passed to Update-DcLdapsCertificate.ps1 each time the task runs.

.PARAMETER LdapsServiceName
    The fully qualified DNS name clients use to connect to the load balanced LDAPS service, for example ldaps.lab.richardhicks.net. This value is passed to Update-DcLdapsCertificate.ps1 each time the task runs, and only certificates that include this name in the subject alternative name are bound. The domain controller's own fully qualified domain name is not required to be present on the certificate.

.PARAMETER ScriptPath
    The full path to Update-DcLdapsCertificate.ps1. The default is a file of that name in the same folder as this script. The file must exist when the task is registered.

.PARAMETER TaskName
    The name of the scheduled task. The default is 'Update DC LDAPS Certificate'.

.INPUTS
    None.

.OUTPUTS
    None. Progress is reported using Write-Verbose.

.EXAMPLE
    .\Register-DcLdapsCertificateTask.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -LdapsServiceName 'ldaps.lab.richardhicks.net'

    Registers the scheduled task using Update-DcLdapsCertificate.ps1 from the same folder as this script. Each time the task runs, only certificates issued from the specified template that include ldaps.lab.richardhicks.net in the subject alternative name are bound.

.EXAMPLE
    .\Register-DcLdapsCertificateTask.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -LdapsServiceName 'ldaps.lab.richardhicks.net' -ScriptPath 'C:\Scripts\Update-DcLdapsCertificate.ps1' -Verbose

    Registers the scheduled task using a copy of Update-DcLdapsCertificate.ps1 in C:\Scripts, with detailed progress output.

.EXAMPLE
    .\Register-DcLdapsCertificateTask.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -LdapsServiceName 'ldaps.lab.richardhicks.net' -WhatIf

    Shows the event log, registry, and scheduled task changes that would be made without making them.

.LINK
    https://github.com/richardhicks/ldaps/blob/master/Register-DcLdapsCertificateTask.ps1

.LINK
    https://github.com/richardhicks/ldaps/blob/master/Update-DcLdapsCertificate.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.0
    Creation Date:  September 21, 2026
    Last Updated:   September 21, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
[OutputType([void])]

Param (

    [Parameter(Mandatory, HelpMessage = 'Enter the OID of the certificate template used to issue the LDAPS certificate.')]
    [ValidatePattern('^\d+(\.\d+)+$')]
    [string]$TemplateOid,

    [Parameter(Mandatory, HelpMessage = 'Enter the fully qualified DNS name clients use to connect to the load balanced LDAPS service, for example ldaps.lab.richardhicks.net.')]
    [ValidatePattern('^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')]
    [string]$LdapsServiceName,

    [ValidateNotNullOrEmpty()]
    [string]$ScriptPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Update-DcLdapsCertificate.ps1'),

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'Update DC LDAPS Certificate'

)

$ErrorActionPreference = 'Stop'

# Event log that records certificate lifecycle events for the local machine and user stores. Event 1006 is raised when a new certificate is installed and event 1001 when a certificate is replaced.
$LifecycleLogName = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
$LifecycleProviderName = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System'

# OID of the Server Authentication enhanced key usage (szOID_PKIX_KP_SERVER_AUTH)
$ServerAuthEkuOid = '1.3.6.1.5.5.7.3.1'

# Registry location and value that control autoenrollment event logging. A value of 0 logs all autoenrollment events to the Application log.
$AutoEnrollmentKeyPath = 'HKLM:\SOFTWARE\Microsoft\Cryptography\AutoEnrollment'
$AutoEnrollmentLogValueName = 'AEEventLogLevel'

# Delay between the trigger event and task start, in ISO 8601 duration format. Allows autoenrollment to finish writing the certificate and private key.
$TriggerDelay = 'PT1M'

# Verify the script to be executed exists before registering a task that depends on it, then resolve it to a full path for the task action
If (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {

    Throw "Update-DcLdapsCertificate.ps1 was not found at '$ScriptPath'. Specify the correct location using the -ScriptPath parameter."

}

$ScriptPath = (Resolve-Path -Path $ScriptPath).Path
Write-Verbose "Using script '$ScriptPath'."

# Ensure the certificate lifecycle event log is enabled. The scheduled task cannot trigger if this log is disabled.
$LogConfiguration = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $LifecycleLogName

If ($LogConfiguration.IsEnabled) {

    Write-Verbose "Event log '$LifecycleLogName' is enabled."

}

ElseIf ($PSCmdlet.ShouldProcess($LifecycleLogName, 'Enable event log')) {

    $LogConfiguration.IsEnabled = $true
    $LogConfiguration.SaveChanges()
    Write-Verbose "Event log '$LifecycleLogName' enabled."

}

# Ensure autoenrollment events are logged to the Application log
$CurrentLogLevel = (Get-ItemProperty -Path $AutoEnrollmentKeyPath -Name $AutoEnrollmentLogValueName -ErrorAction SilentlyContinue).$AutoEnrollmentLogValueName

If ($CurrentLogLevel -eq 0) {

    Write-Verbose "Autoenrollment event logging is already enabled ($AutoEnrollmentLogValueName = 0)."

}

ElseIf ($PSCmdlet.ShouldProcess("$AutoEnrollmentKeyPath\$AutoEnrollmentLogValueName", 'Set value to 0 to enable autoenrollment event logging')) {

    If (-not (Test-Path -Path $AutoEnrollmentKeyPath)) {

        [void](New-Item -Path $AutoEnrollmentKeyPath -Force)

    }

    Set-ItemProperty -Path $AutoEnrollmentKeyPath -Name $AutoEnrollmentLogValueName -Value 0 -Type DWord
    Write-Verbose "Autoenrollment event logging enabled ($AutoEnrollmentLogValueName = 0)."

}

# Event subscription for the task trigger. Matches a new or replaced certificate in the machine store that includes the Server Authentication EKU.
$Subscription = @"
<QueryList>
  <Query Id="0" Path="$LifecycleLogName">
    <Select Path="$LifecycleLogName">
      *[System[Provider[@Name='$LifecycleProviderName'] and (EventID=1001 or EventID=1006)]]
      and
      *[UserData/CertNotificationData[@Context='Machine']/CertificateDetails/EKUs/EKU[@OID='$ServerAuthEkuOid']]
    </Select>
  </Query>
</QueryList>
"@

# Build the event trigger. New-ScheduledTaskTrigger does not support event triggers, so the trigger is created directly from the Task Scheduler CIM class.
$TriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$Trigger = New-CimInstance -CimClass $TriggerClass -ClientOnly
$Trigger.Subscription = $Subscription
$Trigger.Delay = $TriggerDelay
$Trigger.Enabled = $true

# Action: run the update script with Windows PowerShell, bypassing execution policy and hiding the window. The update script enables verbose output itself so its transcript is complete without any additional parameters.
$Argument = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -TemplateOid {1} -LdapsServiceName {2}' -f $ScriptPath, $TemplateOid, $LdapsServiceName
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $Argument

# Principal: run as SYSTEM with highest privileges. The NTDS service certificate store and the private key require this level of access.
$Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest

# Settings: a single instance at a time, with a time limit so a hung run cannot block the next trigger
$Settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$Description = "Runs Update-DcLdapsCertificate.ps1 to bind a newly installed certificate issued from template $TemplateOid and containing the LDAPS service name $LdapsServiceName to the NTDS service certificate store for load balanced LDAPS. Triggered by certificate lifecycle events 1001 and 1006. This task has no time-based trigger."

# Register the task, replacing any existing task with the same name
If ($PSCmdlet.ShouldProcess("Scheduled task '$TaskName'", 'Register event-triggered task')) {

    $TaskParams = @{

        TaskName    = $TaskName
        Description = $Description
        Action      = $Action
        Trigger     = $Trigger
        Principal   = $Principal
        Settings    = $Settings
        Force       = $true

    }

    [void](Register-ScheduledTask @TaskParams)

    # Confirm the registered task carries exactly one trigger and that it is an event trigger
    $RegisteredTask = Get-ScheduledTask -TaskName $TaskName
    $TriggerTypes = @($RegisteredTask.Triggers | ForEach-Object { $_.CimClass.CimClassName })

    If ($TriggerTypes.Count -ne 1 -or $TriggerTypes[0] -ne 'MSFT_TaskEventTrigger') {

        Throw "Scheduled task '$TaskName' was registered but its trigger configuration is not as expected. Trigger types: $($TriggerTypes -join ', ')"

    }

    Write-Verbose "Scheduled task '$TaskName' registered with a single event trigger on '$LifecycleLogName'."

}

# SIG # Begin signature block
# MIIk6wYJKoZIhvcNAQcCoIIk3DCCJNgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAPp2NpPXQqqyOB
# W5q8+4Fm/9M24Xlpa2TE4vwlv+iI5qCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggW0MIIDnKADAgECAhAOxitIKuZQm69NGxw+uiH/MA0GCSqG
# SIb3DQEBDAUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE2MDAwMDAwWhcNMjcwODE3MjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMFkw
# EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOooTPiege6mCA4AriPO+Xh3mymiiZ+3k
# kn31uJifB2ojzzfY7VkAVKhgj+rcVBnofnj2b8OhvAJ4YaQ2Iwuc6aOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQJvGhl
# Ahwi6UKROatrFKBmPLmd5TA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAbaKnnRcJAMHjuWSc2PG/QhJ0jj4hQVwJIbddYDJNxPmD0cxuuorSiR9gX2nl
# ajqNI9N7Kl+FB3oheRTGh/wp4JgZMpCq0qS0zGJ/N6Js+HmVtbkFaPyYxJMXbIWq
# p9zKkoXtSXkpR6nGZnzYkn3EBcRlu4R6hIJHzM/C2PUztH/Hd4fGIryyD69iHvKx
# zotYdlHHY6+X1ACaQnuCz3TLxs3/CDKhPUXesKcISnXHmm4uCwyVdtGyl7wPuZVk
# +rfCIOeWn+XG5J7L8xwhXCPSJ5fKJ5m8/H5cICLR0I7hI4SUiybE1nG5CZ1hKhbW
# abSfNer1dHH/vSYi80YGXCej/88vZeCGQ9/rrjugsg0yN7WCPqNKjEMTYGWkrt37
# lp4cJqULS+alUbL6x1HBdoBStDE2CFmPivL7cCCtnudqCA6b3XB416/FlRo8t4Lw
# Dc2ty+RDKirWM84Zj3ANTVs5fi43rxClBQwngGdqi5TjriKHGTkEKYRIFTViy6Ie
# JDIboOkCFJU5vM7Curvh4rQnw+aM4CyjwnDwnzwcKQVZC3Iy1T4h/FvmpSgu5ouM
# wjdzaR3cSh4OPDRrfBl1YIOoZEOHcshCaHDC46t8+UyAf70BMlrB7Nj84ORTuKTi
# IlU062VzGeREc1KHJqp/S3/NtArpVUVQEgibRxQ99KJCOV8wggawMIIEmKADAgEC
# AhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0Mjkw
# MDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2Rl
# IFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYw
# n6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43i
# CH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1
# hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd
# 6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObar
# YBLj6Na59zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18eb
# MlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYo
# X7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDz
# d5Ea/ttQokbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8S
# kXbev1jLchApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZ
# YIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxW
# EQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTAT
# MAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6P
# vDqZ01bgAhql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V
# 1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+
# 3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcn
# P/2Q0XaG3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgU
# kpn13c5UbdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6Q
# B7BDf5WIIIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3
# kuZOX956rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKL
# QcBIhEuWTatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47v
# tevLt/B3E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0
# qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0
# YW6/aOImYIbqyK+p/pQd52MbOoZWeE4wgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEw
# NDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7
# pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRik
# y4WAawDfU3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5u
# FIS80sZsDwO3BSkUxDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJI
# C5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7
# TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4
# Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QT
# Fg33otX+bFRsIolvykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrL
# l5ya0m5doH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/
# 2nXpQNMu1PT5prW83vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9
# t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv
# 3vUPItdwroczk9icflf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0o
# QLFr0mLywSLaDXQIENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35
# RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7Rn
# OGf8Wj4UNgAdZkfHhHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH2
# 3d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRya
# BVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JE
# TjajHug2AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ
# 9lOCLLYcsQeSWmvKqzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D7
# 3FLje1O5b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94l
# bUveOiJBI+xZEbGRsMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H
# 5Mh7QfieAIjWagkJNt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCya
# tf8R1hSjzSvdN8yWQPT9gzGCBJswggSXAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAusq8xAZWYIGjKBw15tolL
# K7L/IL6sdjHPApp5kmruGTALBgcqhkjOPQIBBQAERjBEAiAY4WG8vxgtLlAB+K/o
# r/EhKQAv+NdRQjD1I3djm80/NQIgacyprJ0I9aaZohUjTLBXp0GhRzGfDUh7yr5/
# 6OQxeCShggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAIT9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwOTIxMjIyNjMzWjAvBgkq
# hkiG9w0BCQQxIgQgPy60uokTnYXLVv1HHdqvCyX2K3csVoz4hy3+xHprWMcwDQYJ
# KoZIhvcNAQEBBQAEggIAeGkWWcG9eJCN+DlR2fAEM4lisHFGv3JrwZpl/NNRcyZy
# msFeBCrt8LT3BkyBSTnW8lxZUlji24Ugus4DGF3iKVW9Mgu0BNL7LBkQpQwn71jY
# LKLRv3Qt4Cu/+VlFwUB6nMyvy16u0AW8XBfSzj0w8u7Jedzmktw1vOY9ppOT/7xo
# 5sqbZWV8Nlpnkm2P4X171AOglAXdBl1QzSgzlcg9SmvcZvCI4z7KAmjj9ds8X+iU
# LgZn0ag/Wcgl3XqfxNu+A9dyiyM53X/J7wJmXW2fwQPaWZp/+1ihe9b27dlzY6mS
# I/Cuew8FND5AI7in4RSRZS9CqgrYF4++qbeDN+rKtwemZBjXMOEe5eMFhLqVL7qo
# aRGahlRuVgmpY4kq8Z9Lu7i5inkVdC2EelafudqoBFXyg1WZsMv3Qxwo6AUBavVd
# +RVCWZzF4xC5JLEALsvyWXJuSSQ7AHHFzwAYOuIgbJZRYARhHh4i74A6QQuV6VAf
# Yh3dhh3CO1LhcohC5aiTrwAgG4roYerxNgV53wWZtIRKNcFNEEbF1vpK1kyESz7l
# YpaFwBYzBtHTs6mC2YhKI4pi38Qvc0g1nM6osbBlvx8HTOVo098UwHhhzXB8jUzf
# QkSS4JWKiL2ctmNPFTd8hgHrpgGwqcTv+WBwCyQCYETprxX2WRFMP+yTWdjYRYA=
# SIG # End signature block
