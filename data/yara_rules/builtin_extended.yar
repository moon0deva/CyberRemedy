// CyberRemedy Built-in YARA Rules v3.0
// Covers: Webshells, RATs, Ransomware, Exploits, Lateral Movement,
//         Credential Theft, Data Exfiltration, C2 Beacons, Rootkits
// All rules written from scratch for CyberRemedy — no external licence required.

// ─── WEBSHELLS ────────────────────────────────────────────────────────────────
rule Webshell_Generic_PHP {
    meta: description="Generic PHP webshell" severity="CRITICAL" mitre="T1505.003"
    strings:
        $eval1 = "eval(" nocase
        $eval2 = "assert(" nocase
        $pass1 = "cmd" nocase
        $pass2 = "shell_exec" nocase
        $pass3 = "passthru" nocase
        $pass4 = "system(" nocase
        $obf1  = "base64_decode" nocase
        $obf2  = "str_rot13" nocase
        $obf3  = "gzinflate" nocase
    condition: (1 of ($eval*)) and (1 of ($pass*)) and (1 of ($obf*))
}

rule Webshell_Generic_ASP {
    meta: description="Generic ASP/ASPX webshell" severity="CRITICAL" mitre="T1505.003"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "CreateObject(\"WScript.Shell\")" nocase
        $cmd3 = "Process.Start(" nocase
        $b64  = "Convert.FromBase64String" nocase
        $eval = "Execute(" nocase
    condition: (1 of ($cmd*)) and (1 of ($b64, $eval))
}

rule Webshell_China_Chopper {
    meta: description="China Chopper webshell signature" severity="CRITICAL" mitre="T1505.003"
    strings:
        $chopper1 = "<%eval request(" nocase
        $chopper2 = "<%execute request(" nocase
        $chopper3 = "eval(Request[" nocase
        condition: any of ($chopper1,$chopper2,$chopper3)
}

rule Webshell_WSO {
    meta: description="WSO PHP webshell" severity="CRITICAL"
    strings:
        $wso1 = "FilesMan" nocase
        $wso2 = "WSO " nocase
        $wso3 = "uname -a" nocase
        $wso4 = "safe_mode" nocase
        condition: any of ($wso1,$wso2,$wso3,$wso4)
}

// ─── RANSOMWARE ───────────────────────────────────────────────────────────────
rule Ransomware_Generic_Note {
    meta: description="Generic ransom note" severity="CRITICAL" mitre="T1486"
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "your files are encrypted" nocase
        $note3 = "All your files" nocase
        $note4 = "bitcoin" nocase
        $note5 = "decrypt" nocase
        $ext1  = ".locked" nocase
        $ext2  = ".encrypted" nocase
        $ext3  = ".enc" nocase
    condition: (2 of ($note*)) or (1 of ($note*) and 1 of ($ext*))
}

rule Ransomware_Vssadmin_Delete {
    meta: description="Shadow copy deletion — ransomware pre-encryption step" severity="CRITICAL" mitre="T1490"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "vssadmin.exe Delete Shadows" nocase
        $s3 = "wmic shadowcopy delete" nocase
        $s4 = "bcdedit /set {default} recoveryenabled No" nocase
        $s5 = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase
    condition: any of them
}

rule Ransomware_WannaCry {
    meta: description="WannaCry ransomware" severity="CRITICAL" mitre="T1486"
    strings:
        $wc1 = "WANACRY!" wide ascii
        $wc2 = "WanaDecryptor" nocase
        $wc3 = "@Please_Read_Me@.txt" nocase
        $wc4 = "tasksche.exe" nocase
        $wc5 = "mssecsvc2.0" nocase
        condition: any of ($wc1,$wc2,$wc3,$wc4,$wc5)
}

rule Ransomware_LockBit {
    meta: description="LockBit ransomware indicators" severity="CRITICAL"
    strings:
        $lb1 = "Restore-My-Files.txt" nocase
        $lb2 = "lockbit" nocase
        $lb3 = ".lockbit" nocase
        $lb4 = "LockBit 2.0" nocase
        condition: any of ($lb1,$lb2,$lb3,$lb4)
}

// ─── REMOTE ACCESS TROJANS (RATs) ─────────────────────────────────────────────
rule RAT_Njrat {
    meta: description="njRAT remote access trojan" severity="CRITICAL" mitre="T1219"
    strings:
        $nj1 = "njq8" nocase
        $nj2 = "HvnRemoteAdmin" nocase
        $nj3 = "njrat" nocase
        $nj4 = "bladabindi" nocase
        $nj5 = "lol.exe" nocase
        condition: any of ($nj1,$nj2,$nj3,$nj4,$nj5)
}

rule RAT_AsyncRAT {
    meta: description="AsyncRAT" severity="CRITICAL" mitre="T1219"
    strings:
        $ar1 = "AsyncRAT" nocase
        $ar2 = "HKLM\\Software\\AsyncRAT" nocase
        $ar3 = "AES_KEY" nocase
        $ar4 = "ServerCertificate" nocase wide
        condition: any of ($ar1,$ar2,$ar3,$ar4)
}

rule RAT_RemcosRAT {
    meta: description="Remcos RAT" severity="CRITICAL" mitre="T1219"
    strings:
        $r1 = "Remcos" nocase
        $r2 = "REMCOS" nocase
        $r3 = "Breaking-Security" nocase
        $r4 = "Remcos_mutex" nocase
        condition: any of ($r1,$r2,$r3,$r4)
}

rule RAT_NetWire {
    meta: description="NetWire RAT" severity="CRITICAL" mitre="T1219"
    strings:
        $nw1 = "NetWire" nocase
        $nw2 = "netwire" nocase
        $nw3 = "HKCU\\NetWire" nocase
        condition: any of ($nw1,$nw2,$nw3)
}

// ─── CREDENTIAL THEFT ─────────────────────────────────────────────────────────
rule CredentialTheft_Mimikatz {
    meta: description="Mimikatz credential dumping tool" severity="CRITICAL" mitre="T1003"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "mimilib" nocase
        $m3 = "sekurlsa::" nocase
        $m4 = "kerberos::" nocase
        $m5 = "lsadump::" nocase
        $m6 = "privilege::debug" nocase
        $m7 = "Invoke-Mimikatz" nocase
        condition: any of ($m1,$m2,$m3,$m4,$m5,$m6,$m7)
}

rule CredentialTheft_LaZagne {
    meta: description="LaZagne password recovery tool" severity="HIGH" mitre="T1555"
    strings:
        $lz1 = "laZagne" nocase
        $lz2 = "lazagne.exe" nocase
        $lz3 = "Retrieve passwords" nocase
        condition: any of ($lz1,$lz2,$lz3)
}

rule CredentialTheft_LSASS_Dump {
    meta: description="LSASS process memory dump" severity="CRITICAL" mitre="T1003.001"
    strings:
        $l1 = "lsass.exe" nocase
        $l2 = "MiniDumpWriteDump" nocase
        $l3 = "SeDebugPrivilege" nocase
        $l4 = "procdump" nocase
        $l5 = "tasklist | findstr lsass" nocase
    condition: (($l1 and $l2) or ($l1 and $l3) or $l4 or $l5)
}

// ─── EXPLOITATION / SHELLCODE ─────────────────────────────────────────────────
rule Exploit_Log4Shell {
    meta: description="Log4Shell JNDI injection attempt" severity="CRITICAL" mitre="T1190"
    strings:
        $j1 = "${jndi:" nocase
        $j2 = "${${lower:j}ndi:" nocase
        $j3 = "${${::-j}${::-n}${::-d}${::-i}" nocase
        $j4 = "jndi:ldap://" nocase
        $j5 = "jndi:rmi://" nocase
        $j6 = "jndi:dns://" nocase
    condition: any of them
}

rule Exploit_ProxyLogon {
    meta: description="ProxyLogon/ProxyShell Exchange exploit pattern" severity="CRITICAL" mitre="T1190"
    strings:
        $p1 = "/ecp/Current/exporttool/" nocase
        $p2 = "/owa/auth/errorFE.aspx" nocase
        $p3 = "X-AnonResource-Backend" nocase
        $p4 = "Autodiscover/Autodiscover.xml" nocase
        condition: any of ($p1,$p2,$p3,$p4)
}

rule Shellcode_Generic {
    meta: description="Generic shellcode patterns" severity="HIGH" mitre="T1055"
    strings:
        $nop  = { 90 90 90 90 90 90 90 90 }
        $fs1  = { 64 A1 30 00 00 00 }  // PEB access (x86)
        $fs2  = { 65 48 8B 04 25 60 00 00 00 }  // PEB access (x64)
        $egg  = "w00tw00t" nocase
        $egg2 = { 63 DE CA DE }
    condition: (($nop and ($fs1 or $fs2)) or $egg or $egg2)
}

// ─── PERSISTENCE ──────────────────────────────────────────────────────────────
rule Persistence_Registry_Run {
    meta: description="Suspicious registry run key modification" severity="HIGH" mitre="T1547.001"
    strings:
        $r1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $r2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $r3 = "reg add" nocase
        $r4 = "RegSetValueEx" nocase
    condition: (1 of ($r*)) and ($r3 or $r4)
}

rule Persistence_Scheduled_Task {
    meta: description="Scheduled task creation for persistence" severity="HIGH" mitre="T1053.005"
    strings:
        $t1 = "schtasks /create" nocase
        $t2 = "schtasks.exe /Create" nocase
        $t3 = "/sc onlogon" nocase
        $t4 = "/sc onstart" nocase
        $t5 = "TaskScheduler" nocase
        $t6 = "Register-ScheduledTask" nocase
    condition: (1 of ($t1,$t2,$t6)) and (1 of ($t3,$t4,$t5))
}

rule Persistence_Startup_Folder {
    meta: description="File placed in startup folder" severity="MEDIUM" mitre="T1547.001"
    strings:
        $s1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $s2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu" nocase
        $s3 = "\\CurrentUser\\Startup" nocase
        condition: any of ($s1,$s2,$s3)
}

// ─── LATERAL MOVEMENT ─────────────────────────────────────────────────────────
rule LateralMovement_PSExec {
    meta: description="PSExec lateral movement tool" severity="HIGH" mitre="T1021.002"
    strings:
        $p1 = "psexec" nocase
        $p2 = "PSEXESVC" nocase
        $p3 = "PsExec Service" nocase
        $p4 = "\\\\%s\\ADMIN$" nocase
        condition: any of ($p1,$p2,$p3,$p4)
}

rule LateralMovement_WMI {
    meta: description="WMI-based lateral movement" severity="HIGH" mitre="T1047"
    strings:
        $w1 = "wmic /node:" nocase
        $w2 = "Win32_Process.Create" nocase
        $w3 = "Invoke-WmiMethod" nocase
        $w4 = "wmiexec" nocase
        $w5 = "Get-WmiObject" nocase
    condition: any of ($w1, $w2, $w3, $w4) or ($w5 and @w5[1] < 100)
}

rule LateralMovement_PassTheHash {
    meta: description="Pass-the-hash attack" severity="CRITICAL" mitre="T1550.002"
    strings:
        $pth1 = "sekurlsa::pth" nocase
        $pth2 = "/ntlm:" nocase
        $pth3 = "pth-winexe" nocase
        $pth4 = "impacket" nocase
        condition: any of ($pth1,$pth2,$pth3,$pth4)
}

// ─── C2 BEACONS ───────────────────────────────────────────────────────────────
rule C2_CobaltStrike {
    meta: description="Cobalt Strike beacon indicators" severity="CRITICAL" mitre="T1071.001"
    strings:
        $cs1 = "cobaltstrike" nocase
        $cs2 = "CobaltStrike" nocase
        $cs3 = "beacon.dll" nocase
        $cs4 = "/updates.rss" nocase
        $cs5 = { 4D 5A }  // MZ header (PE executable)
        $cs6 = { 2F 2F 2F 2F 2F 2F 2F 2F 2F 2F }  // repeated padding
        $cs7 = "ReflectiveDLL" nocase
        $cs8 = "beacon_http" nocase
    condition: any of ($cs1,$cs2,$cs3,$cs7,$cs8) or ($cs4 and $cs5)
}

rule C2_Metasploit_Meterpreter {
    meta: description="Metasploit Meterpreter payload" severity="CRITICAL" mitre="T1059.001"
    strings:
        $m1 = "meterpreter" nocase
        $m2 = "metasploit" nocase
        $m3 = "msfconsole" nocase
        $m4 = "ReflectiveLoader" nocase
        $m5 = "stdapi_" nocase
        condition: any of ($m1,$m2,$m3,$m4,$m5)
}

rule C2_Empire_PowerShell {
    meta: description="PowerShell Empire C2 framework" severity="CRITICAL" mitre="T1059.001"
    strings:
        $e1 = "powershell-empire" nocase
        $e2 = "invoke-empire" nocase
        $e3 = "Empire" nocase
        $e4 = "$wc.DownloadString(" nocase
        $e5 = "-EncodedCommand" nocase
        $e6 = "IEX(" nocase
    condition: (($e4 or $e6) and $e5) or any of ($e1,$e2,$e3)
}

// ─── DATA EXFILTRATION ────────────────────────────────────────────────────────
rule Exfil_DNS_Tunneling {
    meta: description="DNS tunneling for data exfiltration" severity="HIGH" mitre="T1048.003"
    strings:
        $d1 = "iodine" nocase
        $d2 = "dnscat" nocase
        $d3 = "dns2tcp" nocase
        $d4 = "dnscapy" nocase
        condition: any of ($d1,$d2,$d3,$d4)
}

rule Exfil_PowerShell_Upload {
    meta: description="PowerShell data upload to external server" severity="HIGH" mitre="T1041"
    strings:
        $u1 = "WebClient).UploadFile" nocase
        $u2 = "WebClient().UploadString" nocase
        $u3 = "UploadData(" nocase
        $u4 = "Invoke-RestMethod" nocase
        $u5 = "-Method POST" nocase
    condition: (1 of ($u1,$u2,$u3)) or ($u4 and $u5)
}

// ─── ROOTKITS / ANTI-DETECTION ────────────────────────────────────────────────
rule Rootkit_Kernel_Module {
    meta: description="Suspicious Linux kernel module" severity="CRITICAL" mitre="T1014"
    strings:
        $k1 = "sys_call_table" nocase
        $k2 = "kallsyms_lookup_name" nocase
        $k3 = "hide_pid" nocase
        $k4 = "rootkit" nocase
        $k5 = "init_module" nocase
        $k6 = "module_init(" nocase
    condition: ($k5 or $k6) and (2 of ($k1,$k2,$k3,$k4))
}

rule AntiDetect_Sandbox_Evasion {
    meta: description="Sandbox/AV evasion techniques" severity="HIGH" mitre="T1497"
    strings:
        $s1 = "IsDebuggerPresent" nocase
        $s2 = "CheckRemoteDebuggerPresent" nocase
        $s3 = "NtQueryInformationProcess" nocase
        $s4 = "GetTickCount" nocase
        $s5 = "VBOX" nocase
        $s6 = "VirtualBox" nocase
        $s7 = "VMware" nocase
        $s8 = "SbieDll.dll" nocase
        condition: any of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)
}

// ─── NETWORK TOOLS / SCANNERS ─────────────────────────────────────────────────
rule NetworkTool_Nmap {
    meta: description="Nmap network scanner" severity="MEDIUM" mitre="T1046"
    strings:
        $n1 = "Nmap scan report" nocase
        $n2 = "nmap.org" nocase
        $n3 = "/nmap" nocase
        condition: any of ($n1,$n2,$n3)
}

rule NetworkTool_Masscan {
    meta: description="Masscan mass port scanner" severity="MEDIUM" mitre="T1046"
    strings:
        $m1 = "masscan" nocase
        $m2 = "--rate=" nocase
        $m3 = "mass scanner" nocase
        condition: any of ($m1,$m2,$m3)
}

rule NetworkTool_Netcat_Backdoor {
    meta: description="Netcat used as backdoor listener" severity="HIGH" mitre="T1059"
    strings:
        $nc1 = "nc -lvp" nocase
        $nc2 = "nc -e /bin/sh" nocase
        $nc3 = "ncat --exec" nocase
        $nc4 = "nc.exe -l" nocase
        $nc5 = "/bin/bash -i" nocase
        condition: any of ($nc1,$nc2,$nc3,$nc4,$nc5)
}

// ─── OFFICE MACRO MALWARE ─────────────────────────────────────────────────────
rule OfficeMacro_AutoOpen {
    meta: description="Suspicious Office macro auto-execution" severity="HIGH" mitre="T1137"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Document_Open" nocase
        $m3 = "Auto_Open" nocase
        $cmd = "Shell(" nocase
        $ps  = "powershell" nocase
        $dl  = "DownloadFile" nocase
    condition: (1 of ($m*)) and (1 of ($cmd,$ps,$dl))
}

rule OfficeMacro_WScript {
    meta: description="Office macro using WScript for execution" severity="HIGH" mitre="T1059.005"
    strings:
        $w1 = "WScript.Shell" nocase
        $w2 = "CreateObject(\"WScript" nocase
        $w3 = "objShell.Run" nocase
        $ps  = "powershell" nocase
        $cmd = "cmd.exe" nocase
    condition: (1 of ($w*)) and (1 of ($ps,$cmd))
}

// ─── PHISHING ARTIFACTS ───────────────────────────────────────────────────────
rule Phishing_HTML_Credential_Harvest {
    meta: description="HTML credential harvesting page" severity="HIGH" mitre="T1566.002"
    strings:
        $f1  = "<form" nocase
        $inp = "type=\"password\"" nocase
        $act = "action=" nocase
        $sub = "type=\"submit\"" nocase
        $ext = ".php" nocase
        $str = "username" nocase
    condition: $f1 and $inp and $act and $sub and ($ext or $str)
}

// ─── CRYPTOCURRENCY MINERS ────────────────────────────────────────────────────
rule CryptoMiner_Generic {
    meta: description="Cryptocurrency miner" severity="MEDIUM" mitre="T1496"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "xmrig" nocase
        $m3 = "monero" nocase
        $m4 = "cryptonight" nocase
        $m5 = "nicehash" nocase
        $m6 = "minergate" nocase
        $m7 = "--donate-level" nocase
        condition: any of ($m1,$m2,$m3,$m4,$m5,$m6,$m7)
}

// ─── LINUX-SPECIFIC ───────────────────────────────────────────────────────────
rule Linux_Reverse_Shell {
    meta: description="Linux reverse shell one-liner" severity="CRITICAL" mitre="T1059.004"
    strings:
        $rs1 = "bash -i >& /dev/tcp/" nocase
        $rs2 = "0>&1" nocase
        $rs3 = "python -c 'import socket" nocase
        $rs4 = "perl -e 'use Socket" nocase
        $rs5 = "ruby -rsocket" nocase
    condition: ($rs1 and $rs2) or $rs3 or $rs4 or $rs5
}

rule Linux_PrivEsc_SUID {
    meta: description="SUID binary abuse for privilege escalation" severity="HIGH" mitre="T1548.001"
    strings:
        $s1 = "chmod +s" nocase
        $s2 = "chmod u+s" nocase
        $s3 = "find / -perm -4000" nocase
        $s4 = "find / -perm -u=s" nocase
        condition: any of ($s1,$s2,$s3,$s4)
}

rule Linux_Cron_Persistence {
    meta: description="Crontab modification for persistence" severity="MEDIUM" mitre="T1053.003"
    strings:
        $c1 = "crontab -e" nocase
        $c2 = "/etc/cron.d/" nocase
        $c3 = "/var/spool/cron/" nocase
        $c4 = "echo * * * * *" nocase
        condition: any of ($c1,$c2,$c3,$c4)
}
