<#

.SYNOPSIS
    Binds the newest valid certificate issued from a specified certificate template to the NTDS service certificate store on a domain controller for LDAP over TLS (LDAPS).

.DESCRIPTION
    Active Directory Domain Services (AD DS) preferentially uses certificates in the NTDS service's personal certificate store for LDAPS. Certificates enrolled or renewed through autoenrollment land in the local machine personal store, not the NTDS store, so they are not used for LDAPS until they are copied there. This script automates that step so LDAPS certificates can be renewed without manual intervention.

    The following actions are performed:

    - Searches the local machine personal certificate store for certificates issued from the specified template OID. Only certificates that are time valid, have an associated private key, include the Server Authentication enhanced key usage, contain the domain controller's fully qualified domain name in the subject alternative name, and chain to a trusted root are considered. If more than one certificate qualifies, the one with the latest expiration date is selected.
    - Reads the certificates currently bound to the NTDS service store. If the selected certificate is already bound, the import step is skipped.
    - Imports the selected certificate into the NTDS service store and reads the store back to confirm the certificate was added. If verification fails, the script terminates and no existing certificates are removed.
    - Removes any other certificates from the NTDS service store. The newly bound certificate is never removed.
    - Signals AD DS to reload its server certificate using the renewServerCertificate rootDSE operation, then performs a TLS handshake to port 636 and warns if the certificate being served does not match the newly bound certificate.

    If no qualifying certificate is found in the local machine personal store, the script terminates before making any changes. All changes to the NTDS service store support -WhatIf and -Confirm.

    A transcript of each run is written to %ProgramData%\RMHCI\PowerShell\Update-DcLdapsCertificate.log. Verbose output is always enabled so the transcript records each certificate evaluated, the contents of the NTDS service store before any change, each decision made, and a completion summary. The log file is overwritten on each run, and the transcript is stopped whether the script completes normally or terminates with an error. If an error occurs, the error is recorded in the transcript and the script exits with code 1.

    Key outcomes are also written to the Application event log using the event source 'Update-DcLdapsCertificate', which is registered automatically on first run. The following event IDs are used:

    1000 (Information) - New certificate imported into the NTDS service store and verified.
    1001 (Information) - Selected certificate is already bound to the NTDS service store. No import required.
    1002 (Information) - Previous certificate removed from the NTDS service store.
    1003 (Information) - LDAPS verified to be serving the new certificate.
    2000 (Warning) - Previous certificate not found in the NTDS service store during cleanup.
    2001 (Warning) - Unable to signal AD DS to reload its server certificate.
    2002 (Warning) - LDAPS is serving a certificate other than the newly bound certificate.
    2003 (Warning) - Unable to complete a TLS handshake to verify the LDAPS certificate.
    3000 (Error) - The script terminated with an error. No changes are made after this point.

    This script requires Administrator privileges, Windows PowerShell 5.1, and the ServiceCertStore PowerShell module (https://www.powershellgallery.com/packages/ServiceCertStore/).

.PARAMETER TemplateOid
    The object identifier (OID) of the certificate template used to issue the LDAPS certificate. The template OID can be found in the Certificate Templates console (certtmpl.msc) on the Extensions tab of the template under Certificate Template Information, or by running Get-CertificateTemplate from the ADCSTemplate module.

.INPUTS
    None.

.OUTPUTS
    None. Progress is reported using Write-Verbose, which is always enabled so the transcript is complete. Warnings are issued if a certificate cannot be removed or if LDAPS is not yet serving the new certificate. A transcript of each run is written to %ProgramData%\RMHCI\PowerShell\Update-DcLdapsCertificate.log, and key outcomes are written to the Application event log.

.EXAMPLE
    .\Update-DcLdapsCertificate.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042'

    Finds the newest valid certificate issued from the specified template in the local machine personal store, binds it to the NTDS service store, removes any other certificates from the NTDS store, and signals AD DS to reload its LDAPS certificate.

.EXAMPLE
    .\Update-DcLdapsCertificate.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -WhatIf

    Shows which certificate would be imported into the NTDS service store and which certificates would be removed, without making any changes.

.LINK
    https://github.com/richardhicks/ldaps/blob/master/Update-DcLdapsCertificate.ps1

.LINK
    https://www.powershellgallery.com/packages/ServiceCertStore/

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
#Requires -Module ServiceCertStore
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
[OutputType([void])]

Param (

    [Parameter(Mandatory, HelpMessage = 'Enter the OID of the certificate template used to issue the LDAPS certificate.')]
    [ValidatePattern('^\d+(\.\d+)+$')]
    [string]$TemplateOid

)

$ErrorActionPreference = 'Stop'

# Verbose output is always enabled so the transcript records every step of the run, not only warnings and errors
$VerbosePreference = 'Continue'

# Event source used for Application event log entries
$EventSource = 'Update-DcLdapsCertificate'

# Writes an entry to the Application event log and echoes it to the verbose, warning, or error stream so it also appears in the transcript. Each message is prefixed with its event ID so transcript entries can be correlated with event log entries. Event log failures are reported as warnings so they never interrupt the certificate update.
Function Write-ScriptEvent {

    [CmdletBinding()]

    Param (

        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType,

        [Parameter(Mandatory)]
        [string]$Message

    )

    Switch ($EntryType) {

        'Warning' { Write-Warning "Event ${EventId}: $Message" }
        'Error' { Write-Error -Message "Event ${EventId}: $Message" -ErrorAction Continue }
        Default { Write-Verbose "Event ${EventId}: $Message" }

    }

    # Event log entries are not written during a -WhatIf run because no changes are made
    If ($WhatIfPreference) {

        Return

    }

    Try {

        Write-EventLog -LogName Application -Source $EventSource -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop

    }

    Catch {

        Write-Warning "Unable to write event $EventId to the Application event log. $($_.Exception.Message)"

    }

}

# Create the log directory if it does not exist
$LogPath = "$env:ProgramData\RMHCI\PowerShell"

If (-not (Test-Path -Path $LogPath)) {

    [void](New-Item -Path $LogPath -ItemType Directory -Force)

}

# Start the transcript. Start-Transcript overwrites an existing file at the same path, so the log reflects only the most recent run.
Start-Transcript -Path "$LogPath\Update-DcLdapsCertificate.log"

# The Finally block guarantees the transcript is stopped whether the script completes normally or terminates with an error
Try {

    # Register the event log source on first run. Skipped during a -WhatIf run because no changes are made.
    If (-not $WhatIfPreference -and -not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {

        New-EventLog -LogName Application -Source $EventSource
        Write-Verbose "Registered event log source '$EventSource' in the Application log."

    }

    # Name of the service whose certificate store is used for LDAPS. AD DS reads its LDAPS certificate from this store.
    $ServiceName = 'NTDS'

    # OID of the certificate template information extension (szOID_CERTIFICATE_TEMPLATE) found on certificates issued from version 2 and later templates
    $TemplateExtensionOid = '1.3.6.1.4.1.311.21.7'

    # OID of the Server Authentication enhanced key usage (szOID_PKIX_KP_SERVER_AUTH)
    $ServerAuthEkuOid = '1.3.6.1.5.5.7.3.1'

    # The certificate template information extension is displayed as 'Template=<name>(<OID>), Major Version Number=<n>, Minor Version Number=<n>'. Anchoring on the parentheses prevents a partial match against a longer OID that begins with the same value.
    $TemplatePattern = '\({0}\)' -f [regex]::Escape($TemplateOid)

    # Determine the fully qualified domain name of this domain controller for subject alternative name and TLS handshake validation
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $DcFqdn = '{0}.{1}' -f $ComputerSystem.DNSHostName, $ComputerSystem.Domain
    $Now = Get-Date

    Write-Verbose "Update-DcLdapsCertificate starting on $DcFqdn."
    Write-Verbose "Searching Cert:\LocalMachine\My for certificates issued from template '$TemplateOid' valid for '$DcFqdn'."

    # Find all certificates issued from the specified template
    $TemplateCertificates = @(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {

        $TemplateExtension = $_.Extensions[$TemplateExtensionOid]
        $TemplateExtension -and $TemplateExtension.Format($false) -match $TemplatePattern

    })

    Write-Verbose "Found $($TemplateCertificates.Count) certificate(s) issued from template '$TemplateOid'."

    # Evaluate each certificate against the LDAPS requirements and record why any certificate is rejected so the log explains the outcome
    $Candidates = @(ForEach ($Certificate in $TemplateCertificates) {

        $Reasons = @()

        If (-not $Certificate.HasPrivateKey) { $Reasons += 'no private key' }
        If ($Certificate.NotBefore -gt $Now) { $Reasons += "not valid until $($Certificate.NotBefore)" }
        If ($Certificate.NotAfter -le $Now) { $Reasons += "expired $($Certificate.NotAfter)" }
        If ($Certificate.EnhancedKeyUsageList.ObjectId -notcontains $ServerAuthEkuOid) { $Reasons += 'missing Server Authentication EKU' }
        If ($Certificate.DnsNameList.Unicode -notcontains $DcFqdn) { $Reasons += "subject alternative name does not include '$DcFqdn'" }

        # Chain validation is only meaningful for a time valid certificate. Verify() also fails for an expired certificate, which would duplicate the reason above.
        If ($Certificate.NotBefore -le $Now -and $Certificate.NotAfter -gt $Now -and -not $Certificate.Verify()) { $Reasons += 'does not chain to a trusted root or is revoked' }

        If ($Reasons.Count -eq 0) {

            Write-Verbose "Certificate $($Certificate.Thumbprint) ($($Certificate.Subject), expires $($Certificate.NotAfter)) meets all requirements."
            $Certificate

        }

        Else {

            Write-Verbose "Certificate $($Certificate.Thumbprint) ($($Certificate.Subject), expires $($Certificate.NotAfter)) rejected: $($Reasons -join '; ')."

        }

    })

    If ($Candidates.Count -eq 0) {

        Throw "No valid certificate issued from template '$TemplateOid' was found in Cert:\LocalMachine\My. The certificate must be time valid, have a private key, include the Server Authentication EKU, contain '$DcFqdn' in the subject alternative name, and chain to a trusted root. No changes were made."

    }

    # If more than one certificate qualifies, use the one with the latest expiration date
    $NewCertificate = $Candidates | Sort-Object -Property NotAfter -Descending | Select-Object -First 1

    # Capture certificate details before import. Import-ServiceCertificate disposes the certificate object it receives, so it cannot be referenced afterward.
    $NewThumbprint = $NewCertificate.Thumbprint
    $NewSubject = $NewCertificate.Subject
    $NewNotAfter = $NewCertificate.NotAfter

    Write-Verbose "Selected certificate $NewThumbprint ($NewSubject) expiring $NewNotAfter."

    # Read the certificates currently bound to the service store. -ErrorAction Stop is passed explicitly because the script's $ErrorActionPreference does not apply inside module scope.
    $ExistingCertificates = @(Get-ServiceCertificates -ServiceName $ServiceName -ErrorAction Stop)
    $ExistingThumbprints = @($ExistingCertificates | Select-Object -ExpandProperty Thumbprint)

    If ($ExistingCertificates.Count -eq 0) {

        Write-Verbose "The $ServiceName service store is empty."

    }

    Else {

        Write-Verbose "The $ServiceName service store currently contains $($ExistingCertificates.Count) certificate(s)."

        ForEach ($ExistingCertificate in $ExistingCertificates) {

            Write-Verbose "  $($ExistingCertificate.Thumbprint) ($($ExistingCertificate.Subject), expires $($ExistingCertificate.NotAfter))"

        }

    }

    # Track what changed so the completion summary can report it
    $Imported = $false
    $RemovedCount = 0

    # Import the new certificate unless it is already bound
    If ($ExistingThumbprints -contains $NewThumbprint) {

        Write-ScriptEvent -EventId 1001 -EntryType Information -Message "Certificate $NewThumbprint ($NewSubject, expires $NewNotAfter) is already bound to the $ServiceName service store. No import required."

    }

    Else {

        Write-Verbose "Certificate $NewThumbprint is not bound to the $ServiceName service store and will be imported."

        If ($PSCmdlet.ShouldProcess("$ServiceName service certificate store", "Import certificate $NewThumbprint ($NewSubject)")) {

            $ImportResult = Import-ServiceCertificate -ServiceName $ServiceName -Certificate $NewCertificate -ErrorAction Stop

            If (-not $ImportResult) {

                Throw "Import-ServiceCertificate did not report success for certificate $NewThumbprint. No existing certificates were removed."

            }

            # Read the store back to confirm the certificate was added before removing anything
            Write-Verbose "Reading the $ServiceName service store back to confirm certificate $NewThumbprint was added."
            $BoundThumbprints = @(Get-ServiceCertificates -ServiceName $ServiceName -ErrorAction Stop | Select-Object -ExpandProperty Thumbprint)

            If ($BoundThumbprints -notcontains $NewThumbprint) {

                Throw "Certificate $NewThumbprint is not present in the $ServiceName service store after import. No existing certificates were removed."

            }

            Write-ScriptEvent -EventId 1000 -EntryType Information -Message "Certificate $NewThumbprint ($NewSubject, expires $NewNotAfter) was imported into the $ServiceName service store and verified."
            $Imported = $true

        }

    }

    # Remove any other certificates from the service store. The newly bound certificate is never removed.
    $OldThumbprints = @($ExistingThumbprints | Where-Object { $_ -ne $NewThumbprint })

    If ($OldThumbprints.Count -eq 0) {

        Write-Verbose "No other certificates are present in the $ServiceName service store. Nothing to remove."

    }

    Else {

        Write-Verbose "Removing $($OldThumbprints.Count) other certificate(s) from the $ServiceName service store: $($OldThumbprints -join ', ')."

    }

    ForEach ($OldThumbprint in $OldThumbprints) {

        If ($PSCmdlet.ShouldProcess("$ServiceName service certificate store", "Remove certificate $OldThumbprint")) {

            $RemoveResult = Remove-ServiceCertificate -ServiceName $ServiceName -Thumbprint $OldThumbprint -ErrorAction Stop

            If ($RemoveResult) {

                Write-ScriptEvent -EventId 1002 -EntryType Information -Message "Previous certificate $OldThumbprint was removed from the $ServiceName service store."
                $RemovedCount++

            }

            Else {

                Write-ScriptEvent -EventId 2000 -EntryType Warning -Message "Previous certificate $OldThumbprint was not found in the $ServiceName service store and could not be removed."

            }

        }

    }

    # Signal AD DS to reload its server certificate and confirm LDAPS is serving the new certificate
    If ($PSCmdlet.ShouldProcess('Active Directory Domain Services', 'Reload server certificate (renewServerCertificate)')) {

        Try {

            $RootDse = [adsi]'LDAP://localhost/RootDSE'
            $RootDse.Put('renewServerCertificate', 1)
            $RootDse.SetInfo()
            Write-Verbose 'AD DS server certificate reload requested.'

        }

        Catch {

            Write-ScriptEvent -EventId 2001 -EntryType Warning -Message "Unable to signal AD DS to reload its server certificate. AD DS normally detects the new certificate automatically. Error: $($_.Exception.Message)"

        }

        $TcpClient = $null
        $TlsStream = $null

        Try {

            Write-Verbose "Connecting to $DcFqdn on port 636 to verify the certificate LDAPS is serving."

            # Certificate validation is intentionally bypassed here because the purpose is only to read which certificate the server presents
            $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient -ArgumentList $DcFqdn, 636
            $TlsStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList $TcpClient.GetStream(), $false, ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback])
            $TlsStream.AuthenticateAsClient($DcFqdn)
            $ServedCertificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $TlsStream.RemoteCertificate

            If ($ServedCertificate.Thumbprint -eq $NewThumbprint) {

                Write-ScriptEvent -EventId 1003 -EntryType Information -Message "LDAPS on $DcFqdn is serving certificate $NewThumbprint ($NewSubject, expires $NewNotAfter)."

            }

            Else {

                Write-ScriptEvent -EventId 2002 -EntryType Warning -Message "LDAPS on $DcFqdn is serving certificate $($ServedCertificate.Thumbprint) ($($ServedCertificate.Subject), expires $($ServedCertificate.NotAfter)) rather than $NewThumbprint. AD DS may need additional time to pick up the new certificate."

            }

        }

        Catch {

            Write-ScriptEvent -EventId 2003 -EntryType Warning -Message "Unable to complete a TLS handshake to $DcFqdn on port 636 to verify the LDAPS certificate. Error: $($_.Exception.Message)"

        }

        Finally {

            If ($TlsStream) { $TlsStream.Dispose() }
            If ($TcpClient) { $TcpClient.Dispose() }

        }

    }

    # Completion summary so the log states the outcome of the run without the reader having to infer it from the absence of an error
    If ($WhatIfPreference) {

        Write-Verbose 'Update-DcLdapsCertificate completed. No changes were made (WhatIf).'

    }

    ElseIf ($Imported) {

        Write-Verbose "Update-DcLdapsCertificate completed. Certificate $NewThumbprint was imported into the $ServiceName service store and $RemovedCount previous certificate(s) were removed."

    }

    Else {

        Write-Verbose "Update-DcLdapsCertificate completed. Certificate $NewThumbprint was already bound to the $ServiceName service store and $RemovedCount previous certificate(s) were removed."

    }

}

Catch {

    # Record the error in the transcript before exiting. A terminating error that propagates out of the script is rendered by the host only after the transcript has been stopped, so it would otherwise be missing from the log.
    $FailureMessage = "Update-DcLdapsCertificate failed at line $($_.InvocationInfo.ScriptLineNumber). $($_.Exception.Message)"

    # Errors raised by the script's own Throw statements are RuntimeExceptions and the message is self-explanatory. For any other exception, such as one from the ServiceCertStore module or .NET, the exception type and script stack trace identify where it originated.
    If ($_.Exception.GetType() -ne [System.Management.Automation.RuntimeException]) {

        $FailureMessage += " Exception type: $($_.Exception.GetType().FullName)."

    }

    If ($_.ScriptStackTrace) {

        $FailureMessage += "`r`nStack trace:`r`n$($_.ScriptStackTrace)"

    }

    Write-ScriptEvent -EventId 3000 -EntryType Error -Message $FailureMessage
    Exit 1

}

Finally {

    # Stop the transcript. Stop-Transcript throws if the host already stopped transcribing, and that must not mask an error raised by the script itself.
    Try {

        Stop-Transcript

    }

    Catch {

        Write-Verbose 'Transcript was not running.'

    }

}

# SIG # Begin signature block
# MIIk7QYJKoZIhvcNAQcCoIIk3jCCJNoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwfWw7JkZfPe70
# eGZkk3OUZM6eyVHK3sNJZzVjVPWiW6CCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# tf8R1hSjzSvdN8yWQPT9gzGCBJ0wggSZAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA+Br2Iy0PEunPmEBkJRCKh
# Vfh85kF76WK9CtcCyVT6YzALBgcqhkjOPQIBBQAESDBGAiEA/QGr9LvUXh1bfFiH
# /8oHVEuekIuhJt+kgzE0bFG3mq8CIQC7mb4bMYu4A825UkAIcsI9AdpACw4nVR5p
# S9zTP6LoD6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MjEyMTQwMzBaMC8G
# CSqGSIb3DQEJBDEiBCBTA9oJt8U0CIzNbucx/Xoij3FXwsfOdgzCSGS7kn7PTzAN
# BgkqhkiG9w0BAQEFAASCAgADXSM83lYhhxDOiRkaVIRKBbOdVWHD7ZbhQHTPwsnk
# 8fWtIqHptJUKWoB/5O+X+CVwJOEsld9keMW5iMYM9NMUxnAZYbPxRs7hv00r7S96
# 1g3OLnnmsRkzu1L1ljxxWm1emY477oJlTKp6oPf60dpwam1SbAMw+/eFJCxIm9Uw
# S6+d5HrASLxfJWfiRAeo/26Dt+kPhPQ9irWbu5KcBct1eG0HiQxLC1J3m1bCe0/z
# Pf0d/6nlGhnB0l38IgDioBD3U2vZOW0ViaCJ4B8TuP4n98KTaGVZ4Odp/3bsjFK5
# AAvOwCDX94dLiIcQT5BJ1n9FI271wkFa0c3jkU0ZzlNfAWoUhq4ImKbblRxb7Dxi
# QFwgmG0fKtHFzbD7KkG/PH3K0PUIv/9mUqnn4B60KP+ws6gkSLUA1s65FrhEgFLN
# ukxuYXaOWqXxsr85gWTzjhBZzSMXcxuAK40ht64ItCK3ySViyBmLTw6b3G89GxQD
# gp3mpo50ezv93UUwBgm0Ltt1JyFuQCvsnCa/YajgPfNV2QVm8/+gK+BlIEpvjYS+
# ydV1cO3X/YDyXgbBcJ6fFXoM4EmyfZZTNRB1tthtvoNKHyXemxkizL4jpj7qsgC8
# eHIhYmzo6WDp7VmB5ZdhvvpasvYpv0pKEVNNShMq3YwBC2qzwK/U/tYasXQNdAz4
# KA==
# SIG # End signature block
