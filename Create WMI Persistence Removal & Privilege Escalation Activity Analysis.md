**WMI Persistence Removal & Privilege Escalation Activity Analysis**

**System:** IEWIN7 (Windows 7, Sysmon Operational Log)**

****xml: https://github.com/astea-b/dfir-projects/blob/main/WMI%20Persistence.xml****

## ****1\. Executive Summary****

This report provides a forensic analysis of a short Sysmon log capturing activity related to WMI persistence removal and privilege escalation performed through the WinPwnage toolkit. The events demonstrate the use of WMIC to enumerate and delete WMI Event Filters and Filter-to-Consumer Bindings, as well as Python‑based execution of WinPwnage for privilege escalation.

Although the log is compact (training dataset), it illustrates realistic attacker tradecraft aligned with MITRE ATT&CK techniques involving **WMI-based persistence**, **command execution**, and **abuse of legitimate administration tools**.

## ****2\. Observed Activity Summary****

### ****2.1. WinPwnage Launch and Parent Process Chain****

The parent process for all WMIC actions is:

ParentImage: C:\\Python27\\python.exe

ParentCommandLine: python winpwnage.py -u elevate -i 5 -p C:\\Windows\\System32\\cmd.exe

This indicates the execution of WinPwnage’s privilege escalation module (-u elevate) using method ID 5.  
WinPwnage is commonly used for bypassing UAC and obtaining elevated privileges through LOLBins.

**MITRE ATT&CK:**

- **T1548.002 – Bypass User Account Control**
- **T1055 – Process Injection (depending on WinPwnage method)**

### ****2.2. WMIC-Based WMI Persistence Removal****

Several Sysmon Event ID **1 (Process Creation)** logs show WMIC being used to delete WMI persistence artifacts.

#### ****Command 1 – Deleting an Event Filter****

WMIC.exe /namespace:"\\\\root\\subscription" PATH \__EventFilter WHERE Name="BotFilter82" DELETE

**Analysis:**  
This command targets an existing malicious (or test) WMI Event Filter named BotFilter82.  
The namespace root\\subscription is where persistence‑related WMI objects are stored.

**MITRE ATT&CK:**

- **T1546.003 – Event Triggered Execution: Windows Management Instrumentation**

#### ****Command 2 – Deleting Filter-to-Consumer Binding****

WMIC.exe /namespace:"\\\\root\\subscription" PATH \__FilterToConsumerBinding

WHERE Filter='\__EventFilter.Name="BotFilter82"' DELETE

**Analysis:**  
A WMI persistence mechanism requires a **Filter**, **Consumer**, and **Binding**.  
This command removes the Binding that connects the Event Filter with the Consumer (“BotConsumer23”).  
Once the binding is removed, the persistence mechanism becomes non-functional.

**MITRE ATT&CK:**

- **T1546.003 – WMI Event Subscription (persistence removal)**

### ****2.3. Sysmon Event ID 21 – WmiBindingEvent****

Example:

EventType: WmiBindingEvent

Operation: Deleted

Consumer: CommandLineEventConsumer.Name="BotConsumer23"

Filter: \__EventFilter.Name="BotFilter82"

**Analysis:**  
Sysmon confirms that the deletion of the Event Filter and the Consumer Binding was successful.  
This correlates with the earlier WMIC deletion commands.

## ****3\. Interpretation****

The sequence clearly reflects:

1.  **Execution of WinPwnage with elevated privileges**  
    The attacker or analyst executed WinPwnage to gain elevated rights, likely to modify protected WMI objects.
2.  **Removal of WMI persistence artifacts**  
    The actor removed:
    - a WMI Event Filter
    - the Filter‑to‑Consumer Binding
    - the associated CommandLineEventConsumer

These objects (“BotFilter82”, “BotConsumer23”) follow classic naming patterns used in malware test labs.

1.  **Use of Native Windows Tools (LOLbins)**  
    WMIC was used for all operations — aligning with attacker preference for living-off-the-land tools.
2.  **High integrity level context**  
    WMIC and WinPwnage ran under High Integrity, confirming the privilege escalation succeeded.

# ****Summary (MITRE)****

| ****Technique**** | ****Technique ID**** | ****Where Seen in Log**** |
| --- | --- | --- |
| **Bypass User Account Control (UAC)** | **T1548.002** | High IL WMIC.exe executions, WinPwnage elevate‑5 |
| **WMI Event Subscription Manipulation** | **T1546.003** | Creation/deletion of Consumer, Filter, Binding |
| **Artifact Deletion (Defense Evasion)** | **T1070** | Removal of Consumer/Filter/Binding |
| **Scripted Execution (Python)** | **T1059.006** | Parent = python.exe |
| **LSASS Access (Privilege check / token ops)** | **T1003.001** (analytically, not malicious here) | EventID 10 |

## ****5\. Conclusion****

The provided Sysmon log captures a short but realistic snapshot of attacker-like activity where an elevated process (WinPwnage executed via Python) removes WMI persistence artifacts using WMIC. Although the log is part of a training dataset and does not represent a full intrusion kill chain, it accurately demonstrates techniques aligned with MITRE ATT&CK related to WMI persistence, privilege escalation, and living‑off‑the‑land tool usage.

This dataset is suitable for a compact GitHub project demonstrating skills in **log analysis**, **Sysmon forensics**, **MITRE ATT&CK mapping**, and **WMI-based threat techniques**.
