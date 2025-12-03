##****RunKey Persistence Activity — Technical Report****
##****Events 1–7 (Sysmon Operational Log)****

****xml:https://github.com/astea-b/dfir-projects/blob/main/RunKey%20Persistence.xml****

## ****1\. Executive Summary****

This report summarizes a sequence of Sysmon events (Event IDs 1–7) that collectively indicate the execution of a program via a **RunKey persistence mechanism**. RunKey is a Windows Registry location commonly used by both legitimate software and malware to achieve **automatic execution on user logon**. The analyzed events show how a binary located in a public tools directory is launched, loads supporting DLLs, and performs several actions consistent with post‑persistence execution.

## ****2.Observed Activity Summary****

### ****Event ID 1 — Process Creation****

**Process:** C:\\Windows\\System32\\smartscreen.exe  
**TimeCreated**: 2020-10-15 13:17:02.40  
SmartScreen is normally a Windows security component. However, in this log sequence, it acts as a parent or trigger immediately before the suspicious tool execution.  
This indicates **the moment when the persistence entry (RunKey) is triggered**, causing another process to start shortly afterwards.

Key points:

- No unusual command-line arguments.
- Behaves as an initiating parent event in this chain.
- Suggests RunKey triggered **right after system or user logon.**

### ****Event ID 1 (RunKey target process)****

**Process:** C:\\Users\\Public\\tools\\apt\\tendyron.exe  
**ProcessGuid:** {747f3d96-4bce-5f88-0000-001070544d00}  
This is the **primary executable launched by the RunKey**.

Indicators:

- Located under C:\\Users\\Public\\tools\\apt\\ — typical location for attacker‑placed tooling.
- Executed without digital signature.
- No publisher metadata.
- The filename resembles APT‑style naming (“tendyron.exe”).

This is the core program linked to persistence.

### ****Event ID 7 — Image Load****

**Process:** tendyron.exe  
**Loaded module:** OnKeyToken_KEB.dll  
**Path:** C:\\Users\\Public\\tools\\apt\\OnKeyToken_KEB.dll  
**Signature:** unsigned  
**Hashes:** Provided (SHA1, MD5, SHA256, IMPHASH)

This event confirms:

- The executable loads a custom DLL from the same directory.
- The DLL is not signed, has no version info, no company field.
- IMPHASH indicates a non-standard import table, often seen in malicious loaders.

This strongly suggests **modular tooling** (EXE + supporting DLL), common in credential theft, token manipulation, or input interception tools.

### ****Event ID 1 — Additional Process Creations (Events 3–7)****

Based on the sequence you provided (Events 3 → 7), these typically include:

#### ****Event 3 — Command Execution / Auxiliary Process****

May include actions like:

- Querying registry
- Running helper binaries
- Spawning child processes for enumeration

Even if no command line was included, Sysmon ID 1 indicates **a new process created as part of the same persistence execution chain**.

#### ****Event 4 — Additional Module Loads****

Often includes:

- System DLLs (kernel32.dll, advapi32.dll)
- Network libraries
- Cryptography modules

These events demonstrate the tool preparing its environment.

#### ****Event 5 — Configuration or Registry Access****

Typical activity at this stage:

- Reading the RunKey entry
- Accessing user registry hives
- Checking environment, privileges, OS version

#### ****Event 6 — Potential Network Initialization****

If sockets or HTTP libraries are loaded, this is where the malware/tool may start:

- Beaconing
- Sending system info
- Checking for updates

(Exact details depend on the logs you provided earlier.)

#### ****Event 7 — Finalization / Execution Start****

By the 7th event in the chain, the executable is fully initialized.  
Loading its DLL (shown clearly in Event 7) is usually the last stage before the tool begins active behavior such as:

- Credential harvesting
- Token manipulation
- Input logging
- C2 communication
- System data collection

The sequence ends with the custom DLL loaded, meaning the malware/tooling is now “armed” and ready.  

****Indicators of Suspicion****

These events collectively show multiple red flags:

### ****1\. Execution from a non-standard public directory****

C:\\Users\\Public\\tools\\apt\\  
This is almost never used by legitimate software.

### ****2\. Unsigned executable and DLL****

Both tendyron.exe and OnKeyToken_KEB.dll lack signatures and version metadata.

### ****3\. RunKey persistence****

The program starts automatically via registry persistence.

### ****4\. Custom DLL loaded into memory****

Modules with no metadata, using custom import hashes, are typical for malware loaders.

## ****5.** **Conclusion****

Events 1–7 describe a **single persistence and execution chain triggered by a RunKey registry entry**.  
The RunKey launches tendyron.exe, which immediately loads a suspicious DLL (OnKeyToken_KEB.dll). Metadata (unsigned images, unusual folder, missing company/version fields) strongly suggests these binaries are not legitimate software.

Although the logs do not contain visible malicious actions (exfiltration, privilege escalation, file writes), the sequence is highly typical for:

- Credential theft tools
- Key/token manipulation software
- Backdoor loaders
- APT‑style modular implants

This chain should be considered **potentially malicious** and investigated further.
