# ****Sysmon Incident Report — Rundll32****
****xml: https://github.com/astea-b/dfir-projects/blob/main/Rundll32.xml****

## ****1\. Executive Summary****

This report analyzes a short Sysmon log sequence showing a suspicious Rundll32‑based DLL execution (winfire.dll) followed by process injection–level access into wermgr.exe, a registry key creation at a sensitive location, and later activity involving WmiPrvSE.exe.  
Although the sequence is short, it contains several high‑value indicators typically associated with **malicious DLL execution, privilege abuse, and potential persistence attempts**.

## ****2\. Timeline Overview****

### ****Event 1 — Process Creation (Sysmon ID 1)****

**Time:** 22:33:02.059  
**Process:** wermgr.exe (PID 5600)  
**Parent:** rundll32.exe executing:

rundll32.exe c:\\temp\\winfire.dll, DllRegisterServer

**Assessment:**

- Rundll32 launching a DLL from C:\\temp\\ is an anomaly (not a standard Windows directory).
- The DLL uses DllRegisterServer, a known pattern for **malicious DLL proxy loading or registration-based persistence**.

### ****Event 2 — Process Access (Sysmon ID 10)****

**Time:** 22:33:02.050  
**Source:** rundll32.exe (PID 2372)  
**Target:** wermgr.exe (PID 5600)  
**GrantedAccess:** 0x001fffff (full access rights)

**Assessment:**

- Access mask 0x1FFFFF = nearly all possible rights → **process takeover / injection capability**.
- This strongly supports the interpretation that the loaded DLL attempted **code injection or manipulation of wermgr.exe**.

### ****Event 3 — Registry Key Creation (Sysmon ID 12)****

**Time:** 22:33:26.461  
**Actor:** wermgr.exe (same PID 5600)  
**Key:**  
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections

**Assessment:**

- This key is often modified by malware for **proxy manipulation**, **network redirection**, or **traffic exfiltration control**.
- Windows Error Reporting (wermgr.exe) normally does **not** write to this location.
- Given the prior injection‑like access, it is likely the DLL caused wermgr to modify the registry.

### ****Event 4 — Later Clean Process Creation (Sysmon ID 1)****

**Time:** 22:35:26.747  
**Process:** WmiPrvSE.exe (PID 6748)  
**Command:**

wmiprvse.exe -secured -Embedding

**Assessment:**

- WmiPrvSE is legitimate.
- However, many malware families trigger WMI Provider Host shortly after registry or process manipulation to continue execution or perform lateral actions.
- Parent listed as 00000000-0000-0000… — normal for system‑initialized WMI, **but relevant in context** because it starts 2 minutes after the DLL chain.

## ****3\. Command Line & Behavioral Analysis****

### ****3.1 Rundll32 Execution****

rundll32.exe c:\\temp\\winfire.dll, DllRegisterServer

**Red flags:**

- Non‑system path (c:\\temp\\).
- Manual DLL export call.
- Parent Rundll32 for suspicious DLL loads is a classic TTP:  
    **MITRE ATT&CK: T1218.011 — Rundll32 Execution**.

**Interpretation:**  
Likely execution of a dropped payload or registration‑based persistence loader.

### ****3.2 wermgr.exe Follow‑up Behavior****

wermgr.exe is normally launched by the system to handle crash reporting.  
But here:

- It is a child of Rundll32 → highly abnormal.
- It receives full access rights from Rundll32 → indicates forced manipulation.
- It performs registry writes in an unusual hive → possible misuse for persistence or network config manipulation.

This combination strongly suggests **wermgr.exe was hijacked as a proxy process**.

### ****3.3 Registry Modification****

Modified key:

HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections

Possible malicious purposes:

- Reconfigure system proxy → command/control redirection.
- Inject WPAD / malicious PAC configurations.
- Influence browser/system web traffic silently.

### ****3.4 WmiPrvSE Launch****

wmiprvse.exe -secured -Embedding

This launch may be:

1.  **Benign system activity**, or
2.  **Triggered via WMI subscription** if the DLL established persistence.

The short time proximity makes it relevant but not conclusive.

## ****4\. High‑Level Interpretation****

The event chain matches a common lightweight infection pattern:

1.  **Execution** of suspicious DLL via Rundll32.
2.  **Privilege abuse / process manipulation** into a trusted Microsoft binary (wermgr.exe).
3.  **Registry modification** consistent with persistence or network tampering.
4.  **System service activation** (WMI) shortly afterward.

While the sequence is short, it contains **high‑confidence indicators of DLL‑based injection and post‑exploitation actions**.

## ****5\. MITRE ATT&CK and Description****

| Event | Description | MITRE ATT&CK |
| --- | --- | --- |
| Rundll32 loading DLL | Suspicious module execution | T1218.011 |
| AccessMask 0x1FFFFF | Process injection capabilities | T1055 |
| Registry modification | Persistence / proxy manipulation | T1112 |
| WmiPrvSE follow‑up | WMI‑based execution | T1047 |

## ****6\. Conclusion****

Even though the dataset is very short, it displays behaviors strongly aligned with malicious DLL execution, privilege escalation, and registry‑based modification.  
As a standalone case, this chain is sufficient for a full report page (and can be merged with the Run‑Key log later if you want a combined multi‑stage infection scenario).
