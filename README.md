# Domain Controller LDAPS Certificate Automation

[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/ldaps/blob/main/LICENSE)

Automates binding autoenrolled certificates to the NTDS service certificate store on Windows Server domain controllers so LDAP over TLS (LDAPS) certificates renew without manual intervention.

## Overview

Active Directory Domain Services (AD DS) preferentially uses certificates in the NTDS service's personal certificate store for LDAPS. Certificates enrolled or renewed through autoenrollment land in the local machine personal store, not the NTDS store, so they are not used for LDAPS until they are copied there. Left unattended, a renewed certificate sits unused while LDAPS continues to serve the expiring one.

Two scripts work together to close that gap:

| Script | Purpose |
|--------|---------|
| `Update-DcLdapsCertificate.ps1` | Finds the newest valid certificate issued from a specified template, binds it to the NTDS service store, removes any previous certificates, and verifies LDAPS is serving the new certificate |
| `Register-DcLdapsCertificateTask.ps1` | Registers an event-triggered scheduled task that runs `Update-DcLdapsCertificate.ps1` whenever a new server authentication certificate is installed on the domain controller |

Run `Register-DcLdapsCertificateTask.ps1` once on each domain controller. From then on, each autoenrollment renewal triggers `Update-DcLdapsCertificate.ps1` automatically.

> **Important:** Both scripts must be run on the domain controller itself. They operate on the local certificate stores and the local AD DS instance and do not support remote targets.

## Requirements

- Windows Server domain controller with Windows PowerShell 5.1
- Must be run as Administrator
- The [ServiceCertStore](https://www.powershellgallery.com/packages/ServiceCertStore/) PowerShell module installed on the domain controller (required by `Update-DcLdapsCertificate.ps1`)
- A certificate template configured for domain controller LDAPS that includes the Server Authentication enhanced key usage and the domain controller's FQDN in the subject alternative name
- Certificate autoenrollment configured so domain controllers enroll and renew certificates from that template

Install the ServiceCertStore module on each domain controller with:

```powershell
Install-Module -Name ServiceCertStore -Scope AllUsers
```

## Update-DcLdapsCertificate.ps1

Binds the newest valid certificate issued from a specified certificate template to the NTDS service certificate store.

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `TemplateOid` | Yes | Object identifier (OID) of the certificate template used to issue the LDAPS certificate. Find it in the Certificate Templates console (`certtmpl.msc`) on the Extensions tab of the template under Certificate Template Information, or by running `Get-CertificateTemplate` from the ADCSTemplate module |

### What the Script Does

1. Searches the local machine personal certificate store for certificates issued from the specified template OID and evaluates each one. A certificate qualifies only if it is time valid, has an associated private key, includes the Server Authentication enhanced key usage, contains the domain controller's FQDN in the subject alternative name, and chains to a trusted root. Each certificate and the reason it was accepted or rejected is recorded in the log
2. Selects the qualifying certificate with the latest expiration date. If no certificate qualifies, the script terminates before making any changes
3. Reads the certificates currently bound to the NTDS service store and records them in the log. If the selected certificate is already bound, the import step is skipped
4. Imports the selected certificate into the NTDS service store and reads the store back to confirm it was added. If verification fails, the script terminates and no existing certificates are removed
5. Removes any other certificates from the NTDS service store. The newly bound certificate is never removed
6. Signals AD DS to reload its server certificate using the `renewServerCertificate` rootDSE operation
7. Performs a TLS handshake to port 636 and warns if the certificate being served does not match the newly bound certificate
8. Writes a completion summary stating whether the certificate was imported or already bound and how many previous certificates were removed

### Logging

A transcript of each run is written to `%ProgramData%\RMHCI\PowerShell\Update-DcLdapsCertificate.log`. Verbose output is always enabled, so the transcript records each certificate evaluated, the contents of the NTDS service store before any change, each decision made, and the completion summary. The log file is overwritten on each run. If an error occurs, the error is recorded in the transcript and the script exits with code 1.

Key outcomes are also written to the Application event log using the event source `Update-DcLdapsCertificate`, which is registered automatically on first run. Transcript entries carry the same event ID so the two logs can be correlated.

| Event ID | Level | Meaning |
|----------|-------|---------|
| 1000 | Information | New certificate imported into the NTDS service store and verified |
| 1001 | Information | Selected certificate is already bound to the NTDS service store. No import required |
| 1002 | Information | Previous certificate removed from the NTDS service store |
| 1003 | Information | LDAPS verified to be serving the new certificate |
| 2000 | Warning | Previous certificate not found in the NTDS service store during cleanup |
| 2001 | Warning | Unable to signal AD DS to reload its server certificate |
| 2002 | Warning | LDAPS is serving a certificate other than the newly bound certificate |
| 2003 | Warning | Unable to complete a TLS handshake to verify the LDAPS certificate |
| 3000 | Error | The script terminated with an error. No changes are made after this point |

### Examples

**Bind the newest certificate from the template:**

```powershell
.\Update-DcLdapsCertificate.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042'
```

**Preview the changes without making them:**

```powershell
.\Update-DcLdapsCertificate.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -WhatIf
```

## Register-DcLdapsCertificateTask.ps1

Registers a scheduled task that runs `Update-DcLdapsCertificate.ps1` in response to certificate installation events on the domain controller.

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `TemplateOid` | Yes | OID of the certificate template used to issue the LDAPS certificate. Passed to `Update-DcLdapsCertificate.ps1` each time the task runs |
| `ScriptPath` | No | Full path to `Update-DcLdapsCertificate.ps1`. Defaults to a file of that name in the same folder as this script. The file must exist when the task is registered |
| `TaskName` | No | Name of the scheduled task. Defaults to `Update DC LDAPS Certificate` |

### What the Script Does

1. Verifies that `Update-DcLdapsCertificate.ps1` exists at the specified path
2. Ensures the `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` event log is enabled. This log is the source of the trigger event and is enabled by default, but is re-enabled if it has been turned off
3. Sets the `AEEventLogLevel` registry value to 0 so autoenrollment writes detailed events to the Application log. This does not affect the trigger but provides a record of each autoenrollment pass for troubleshooting
4. Registers the scheduled task to run as SYSTEM with highest privileges, using Windows PowerShell to execute `Update-DcLdapsCertificate.ps1` with the specified template OID. An existing task with the same name is replaced
5. Confirms the registered task carries exactly one trigger and that it is an event trigger

### How the Task Is Triggered

The task is triggered only by events. It has no time-based trigger and never runs on a schedule. The trigger subscribes to the certificate lifecycle event log and fires on event ID 1006 (a new certificate has been installed) or event ID 1001 (a certificate has been replaced) where the certificate was installed in the machine context and includes the Server Authentication enhanced key usage. Certificates installed in a user context, and machine certificates without the Server Authentication EKU, do not trigger the task.

A one minute delay is applied before the task starts so autoenrollment has finished writing the certificate and private key. The task runs a single instance at a time with a 30 minute execution time limit so a hung run cannot block the next trigger.

### Examples

**Register the task using the update script in the same folder:**

```powershell
.\Register-DcLdapsCertificateTask.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042'
```

**Register the task using a copy of the update script in a different folder:**

```powershell
.\Register-DcLdapsCertificateTask.ps1 `
    -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' `
    -ScriptPath 'C:\Scripts\Update-DcLdapsCertificate.ps1'
```

**Preview the changes without making them:**

```powershell
.\Register-DcLdapsCertificateTask.ps1 -TemplateOid '1.3.6.1.4.1.311.21.8.8722825.6961687.14830235.11733548.12561660.205.9081263.14230042' -WhatIf
```

## Notes

- Both scripts support `-WhatIf` and `-Confirm`. During a `-WhatIf` run of `Update-DcLdapsCertificate.ps1`, a transcript is still written but no event log entries are created.
- `Update-DcLdapsCertificate.ps1` is idempotent. If the newest qualifying certificate is already bound to the NTDS service store, it reports event 1001 and makes no changes. It is safe to run manually at any time.
- Because certificate installation events are also raised when a certificate is installed manually, the scheduled task can run in response to a manual installation of a qualifying certificate. This has no effect unless the installed certificate was issued from the specified template.
- Place `Update-DcLdapsCertificate.ps1` in a location that persists on the domain controller, such as `C:\Scripts`, before registering the task. The scheduled task references the script by its full path and will fail if the file is later moved or deleted.
- The scheduled task runs as SYSTEM. The NTDS service certificate store and the certificate private key require this level of access.
- After a new certificate is bound, AD DS may take a short time to begin serving it. Event 2002 indicates the old certificate is still being served at the moment of verification and is usually transient. Run `Update-DcLdapsCertificate.ps1` again or check the log on the next trigger if the warning persists.
- To review recent runs, check the transcript at `%ProgramData%\RMHCI\PowerShell\Update-DcLdapsCertificate.log` and filter the Application event log for the source `Update-DcLdapsCertificate`.

## Additional Resources

- [Enable LDAP over SSL with a third-party certification authority](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority)
- [ServiceCertStore PowerShell Module](https://www.powershellgallery.com/packages/ServiceCertStore/)
- [Richard M. Hicks Consulting Blog](https://directaccess.richardhicks.com/)
- [LDAPS GitHub Repository](https://github.com/richardhicks/ldaps/)

## License

Licensed under the MIT License. See [LICENSE](https://github.com/richardhicks/ldaps/blob/main/LICENSE) for details.

## Author

**Richard Hicks**  
Richard M. Hicks Consulting, Inc.  
[rich@richardhicks.com](mailto:rich@richardhicks.com)  
[https://www.richardhicks.com/](https://www.richardhicks.com/)
