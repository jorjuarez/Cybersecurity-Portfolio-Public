### Project: PwnCrypt Ransomware Project Appendix

#### Summmary:
This threat hunt was performed in Microsfot Azure and Defender XDR for End-Point. Below you'll see tables used with Sentinel (SIEM), KQL commands, and MITRE ATT&CK® Framework Mapping. 

#### KQL Appendix:

#### Tracing PowerShell-Initiated pwncrypt.ps1 Download Connection
```kql
let target_device = "arcwin10";
DeviceNetworkEvents
| where DeviceName == target_device and Timestamp == datetime(2025-05-10T19:01:44.3886333Z)
| project Timestamp, ActionType, InitiatingProcessCommandLine, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileSize
| where isnotempty( RemoteUrl)
```

Query Result:
| Field                       | Value                                                              |
| :-------------------------- | :----------------------------------------------------------------- |
| Timestamp                   | May 10, 2025 2:01:44 PM                                            |
| ActionType                  | ConnectionSuccess                                                  |
| InitiatingProcessCommandLine| powershell.exe                                                   |
| RemoteUrl                   | hxxps://raw[.]githubusercontent[.]com                            |
| InitiatingProcessAccountName| arcanalyst1                                                      |
| InitiatingProcessFileSize   | 455680                                                           |

#### Confirming `pwncrypt.ps1` Script Execution on `arcwin10`

After being downloaded, the `pwncrypt.ps1` script was immediately executed. The initial PowerShell instance used `cmd.exe` to launch a new PowerShell process, which ran the script using a policy bypass (`powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`).

```kql
let target_device = "arcwin10";
let start_time = datetime(2025-05-10 18:50:00Z); //May 10, 2025 1:50:00 PM CDT
let end_time = datetime(2025-05-10 19:21:00Z); //May 10, 2025 2:21:00 PM CDT
DeviceProcessEvents
| where DeviceName == target_device
| where Timestamp between (start_time .. end_time )
| project Timestamp,AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, FileSize, AdditionalFields
| where InitiatingProcessFileName contains "powershell" and AccountName == "arcanalyst1"
| sort by Timestamp desc
```

Query Result:
| Field                       | Value                                                              |
| :-------------------------- | :----------------------------------------------------------------- |
| Timestamp                   | May 10, 2025 2:01:44 PM                                            |
| AccountName                 | arcanalyst1                                                      |
| InitiatingProcessFileName   | powershell.exe                                                   |
| InitiatingProcessCommandLine| powershell.exe                                                   |
| ProcessCommandLine          | "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1 |
| FileName                    | cmd.exe                                                          |
| FileSize                    | 289792                                                           |
| AdditionalFields            | {"DesktopName":"Winsta0\\Default"}                               |
