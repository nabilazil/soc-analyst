# 🔍 LNK-Analyzer: Safe Phishing Shortcut Triage Tool

A lightweight, native PowerShell script designed for SOC Analysts and Incident Responders to safely analyze malicious `.lnk` (Windows Shortcut) files **without execution**.

## 🎯 Why This Tool? (The Problem)
During phishing investigations, analysts often encounter suspicious `.lnk` files. Manually checking file properties (`Right-click > Properties > Shortcut`) is:
1. **Time-consuming** when dealing with multiple files.
2. **Risky**, as accidental execution can compromise the analyst's machine.
3. **Prone to human error** when parsing complex, obfuscated PowerShell arguments.

This tool automates the triage process, providing instant, color-coded risk assessments.

## ⚙️ Key Features
- ✅ **Safe Analysis:** Uses the native `WScript.Shell` COM object to parse file metadata (Target, Arguments, Icon) as *data only*, preventing accidental execution.
- 🔍 **IOC Extraction:** Automatically extracts the Target Path, Command-Line Arguments, Working Directory, and Spoofed Icon location.
- 🚨 **Regex-Based Detection:** Flags suspicious patterns like `powershell.exe`, `cmd.exe`, `http`, `DownloadFile`, `IEX`, or `-WindowStyle hidden`.
- 🎨 **Color-Coded Output:** Provides clear, instant visual feedback (Green = Safe, Yellow = Warning, Red = Critical/Malicious).

## 🛠️ Technical Highlights
- **100% Native:** Built entirely in PowerShell. No third-party libraries (like Python's `pylnk3`) or external dependencies required.
- **Enterprise-Ready:** Can be deployed and executed immediately on any standard Windows endpoint within a corporate SOC environment.

## 🚀 Usage

1. Open PowerShell as Administrator (or standard user).
2. If execution is restricted, bypass it for the current session:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
3. Run the script against the suspicious .lnk file:
powershell

1
   .\Analyze-LNK.ps1 -LnkPath "C:\Path\To\Suspicious\file.lnk"

<img width="1489" height="659" alt="Image" src="https://github.com/user-attachments/assets/917598ef-5828-42bd-bedc-aa2b926faf14" />
https://github.com/nabilazil/soc-analyst/issues/1#issue-5135103849
   
