code: 

<#
.SYNOPSIS
    Safely analyzes .lnk (Windows Shortcut) files for malicious indicators without execution.

.DESCRIPTION
    This script uses the native WScript.Shell COM object to parse .lnk file metadata 
    (Target, Arguments, Working Directory, Icon). It then applies Regex-based detection 
    rules to identify common phishing and malware delivery techniques (e.g., hidden PowerShell, 
    remote downloads). Designed for SOC Analysts and Incident Responders for rapid, safe triage.

.AUTHOR
    Nabil Azil (SOC Analyst / Security Enthusiast)
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the .lnk file to analyze")]
    [string]$LnkPath
)

# 1. Validation: Ensure the file exists before proceeding
if (-Not (Test-Path $LnkPath)) {
    Write-Host "❌ Error: File not found at $LnkPath" -ForegroundColor Red
    exit
}

# 2. Safe Parsing: Use native Windows COM object to read metadata WITHOUT executing the file
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($LnkPath)
} catch {
    Write-Host "❌ Error: Failed to parse the .lnk file. It might be corrupted or not a valid shortcut." -ForegroundColor Red
    exit
}

# 3. Reporting: Display extracted metadata clearly
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 🔍 LNK Analysis Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "📁 File Name   : $(Split-Path $LnkPath -Leaf)"
Write-Host "🎯 Target Path : $($shortcut.TargetPath)"
Write-Host "⚙️ Arguments   : $($shortcut.Arguments)"
Write-Host "📂 Work Dir    : $($shortcut.WorkingDirectory)"
Write-Host "🖼️ Icon        : $($shortcut.IconLocation)"
Write-Host "========================================" -ForegroundColor Cyan

# 4. Detection Logic: Flag suspicious patterns (IOCs)
$IsSuspicious = $false

# Check for suspicious executables in the Target path
if ($shortcut.TargetPath -match "(?i)powershell|cmd|wscript|cscript|mshta|rundll32") {
    Write-Host "⚠️ WARNING: Suspicious executable detected in Target!" -ForegroundColor Yellow
    $IsSuspicious = $true
}

# Check for malicious behaviors in the Arguments (Downloads, hidden execution, obfuscation)
if ($shortcut.Arguments -match "(?i)http|DownloadFile|IEX|Invoke-WebRequest|Invoke-Expression|WindowStyle hidden|-w hidden|-ep bypass") {
    Write-Host "🚨 CRITICAL: Malicious payload download or hidden execution detected!" -ForegroundColor Red
    $IsSuspicious = $true
}

# 5. Final Conclusion based on detection logic
Write-Host "========================================" -ForegroundColor Cyan
if ($IsSuspicious) {
    Write-Host "🛑 CONCLUSION: This LNK file is highly likely to be MALICIOUS." -ForegroundColor Red
    Write-Host "💡 ACTION: Extract the URL/IP from Arguments and block it in the SIEM/Firewall." -ForegroundColor Yellow
} else {
    Write-Host "✅ CONCLUSION: No obvious malicious indicators found." -ForegroundColor Green
    Write-Host "💡 NOTE: Always verify the Target path manually if unsure." -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan
