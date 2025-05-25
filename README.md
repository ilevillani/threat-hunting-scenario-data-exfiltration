# Data Exfiltration from PIP’d Employee

---

## 📋 Executive Summary  

An insider threat scenario targeting `windows-target-1` was investigated after an employee on a PIP (John Doe) potentially tried to steal sensitive data. Using Microsoft Defender for Endpoint, we discovered silent installation of 7-Zip, automated archiving of employee records, and exfiltration over HTTPS to an Azure storage account. No USB transfer was used. Immediate containment and remediation steps were taken. 

---

## 🛠️ 1. Preparation  

**Goal:** Define hypothesis and scope.  
**Hypothesis:** As an unrestricted administrator, the employee could use PowerShell to archive and exfiltrate data.

---

## 🗄️ 2. Data Collection  
**Goal:** Inspect logs from key MDE tables:  

`DeviceFileEvents`
`DeviceProcessEvents`
`DeviceNetworkEvents`

---

## 🔎 3. Data Analysis

**📦 3.1 File Archiving Detection**

I did a search within MDE DeviceFileEvents for any activities with zip files, and found activity of archiving files and moving to a “backup” folder:

```kql

DeviceFileEvents
| where DeviceName == "ile-vm-threathu"
| where FileName endswith ".zip"
| order by Timestamp desc

```

![image](https://github.com/user-attachments/assets/9752ebf3-b8d3-4ea6-aec7-06d15896d4b9)

**🕒 3.2 Process Activity Around Archive**

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time, a powershell script silently installed 7zip, and then used it to zip up employee data into an archive:

```kql

let VMName = "ile-vm-threathu";
let specificTime = datetime(2025-05-25T10:02:50.8941865Z);
DeviceProcessEvents
| where Timestamp between ((specificTime -2m) .. (specificTime +2m))
| where DeviceName  == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```

![image](https://github.com/user-attachments/assets/31bf6d91-663f-4bce-8efb-8037c942c19f)

**🌐 3.3 Network Exfiltration Detection**

I searched around the same time period for any evidence of exfiltration from the network, and found an instance of a connection through port 443 to exfiltrate data out of the network:

```kql

let VMName = "ile-vm-threathu";
let specificTime = datetime(2025-05-25T10:02:51.0643198Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime -2m) .. (specificTime +2m))
| where DeviceName == VMName
| order by Timestamp desc

```

![image](https://github.com/user-attachments/assets/84540360-48f0-4bcd-bdf6-6ec4cbf47210)

![image](https://github.com/user-attachments/assets/bfb382ed-5481-441b-ab33-2d34303a8cc2)

As further evidence, the script inspection shows the Azure storage account meant to store the stolen data matches the one in the log:

![image](https://github.com/user-attachments/assets/bdaa0504-76dc-4b59-87a1-14f74c3079c2)

*IOCs of sensitive data exfiltration on the employee’s machine*

![image](https://github.com/user-attachments/assets/a183cef1-28c6-4340-8560-81fa89b93020)

**💾 3.4 USB Transfer Check**

I then checked the logs to see if the employee transferred the data to a USB drive, but there is no evidence of it. The query below outputs no results:

```kql

let VMName = "ile-vm-threathu";
DeviceEvents
| where DeviceName  == VMName
| where ActionType == "UsbDriveMounted"

```

## 🕵️‍♂️ 4. Investigation & TTP Mapping 🔍

| Tactic          | Technique ID   | Technique Name            | Procedure                                                |
|-----------------|----------------|---------------------------|----------------------------------------------------------|
| Execution       | **T1059.001**  | PowerShell                | Silent installer & archiving scripts :contentReference  |
| Initial Access  | **T1105**      | Ingress Tool Transfer     | Downloading and installing `7z.exe` :contentReference    |
| Collection      | **T1560.001**  | Archive Collected Data    | Creating `employee-data-*.zip` archives :contentReference |
| Exfiltration    | **T1571**      | Non-Standard Port         | Outbound HTTPS to Azure using port 443 :contentReference |
| Exfiltration    | **T1567.002**  | Exfiltration to Cloud Storage | Uploading archives to Azure storage :contentReference     |

## 🛡️ 5. Response & Remediation

**🚧 Containment**

Immediately isolated the system upon discovering the archiving of sensitive data.

**📡 Monitoring & Detection**

I created an alert to detect when employees create an excessive amount of zip files as per usual standards within the organization. The known backups are excluded from the alert. The alert may also be set to automatically isolate the machine as well.

```kql

DeviceFileEvents
| where Timestamp >= ago(1h)                                // only zip activity in the last hour
| where FileName endswith ".zip"
| where not(ParentProcessFileName in~ ("backup.exe","robocopy.exe"))  // exclude known backup utilities
| where RequestAccountName !in~ ("svc-backup","SYSTEM")               // exclude service accounts
| summarize ZipCount = count() by RequestAccountName, DeviceName
| where ZipCount > 10                                          // alert if >10 archives/hour
| project
    AlertTime = now(),
    DeviceName,
    RequestAccountName,
    ZipCount
| sort by ZipCount desc

```

I created an alert to be notified when an installation binary (e.g. 7z.exe) is silently executed.

```kql
DeviceProcessEvents
| where Timestamp >= ago(1h)                                                 // limit to last hour 
| where FileName endswith ".exe"                                             // target installer 
| where ProcessCommandLine has_any("-y","--silent","/S")                     // common silent flags 
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine  

```

**📝 Documentation**

Finally, I relayed the information to the employees manager, including everything with the archives being created at regular intervals via powershell script. There was clear evidence of exfiltration. Standing by for further instructions from management.







