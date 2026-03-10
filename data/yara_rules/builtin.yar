// CyberRemedy Built-in YARA Rules v2.0

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool strings"
        mitre = "T1003.001"
        severity = "CRITICAL"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa" nocase
        $s3 = "lsadump" nocase
        $s4 = "kerberos::list" nocase
    condition:
        any of them
}

rule PowerShell_Encoded_Command {
    meta:
        description = "Detects Base64 encoded PowerShell commands"
        mitre = "T1059.001"
        severity = "HIGH"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "powershell" nocase
        $b64  = /[A-Za-z0-9+\/]{50,}={0,2}/
    condition:
        ($enc1 or $enc2) and $enc3 and $b64
}

rule Reverse_Shell_Bash {
    meta:
        description = "Detects bash reverse shell one-liners"
        mitre = "T1059.004"
        severity = "CRITICAL"
    strings:
        $s1 = "bash -i >& /dev/tcp/" nocase
        $s2 = "0>&1" nocase
        $s3 = "/dev/tcp/" nocase
    condition:
        2 of them
}

rule Netcat_Backdoor {
    meta:
        description = "Detects netcat used as a backdoor"
        mitre = "T1059"
        severity = "HIGH"
    strings:
        $nc1 = "nc -l" nocase
        $nc2 = "ncat -l" nocase
        $nc3 = "netcat -l" nocase
        $nc4 = "nc.exe" nocase
        $e   = "-e /bin/sh" nocase
        $e2  = "-e cmd.exe" nocase
    condition:
        any of ($nc*) and any of ($e*)
}

rule Webshell_PHP {
    meta:
        description = "Detects common PHP webshell patterns"
        mitre = "T1505.003"
        severity = "CRITICAL"
    strings:
        $e1 = "eval(base64_decode" nocase
        $e2 = "eval(gzinflate" nocase
        $e3 = "eval(str_rot13" nocase
        $s1 = "$_POST" nocase
        $s2 = "$_GET" nocase
        $cmd = "system(" nocase
        $cmd2 = "shell_exec(" nocase
        $cmd3 = "passthru(" nocase
    condition:
        any of ($e*) or (any of ($s*) and any of ($cmd*))
}

rule SQL_Injection_Payload {
    meta:
        description = "Detects SQL injection attempt patterns"
        mitre = "T1190"
        severity = "HIGH"
    strings:
        $s1 = "' OR '1'='1" nocase
        $s2 = "UNION SELECT" nocase
        $s3 = "DROP TABLE" nocase
        $s4 = "1=1--" nocase
        $s5 = "'; DROP" nocase
        $s6 = "xp_cmdshell" nocase
    condition:
        any of them
}

rule Ransomware_Extension_List {
    meta:
        description = "Detects ransomware file extension patterns in traffic"
        mitre = "T1486"
        severity = "CRITICAL"
    strings:
        $e1 = ".locky" nocase
        $e2 = ".encrypted" nocase
        $e3 = ".crypto" nocase
        $e4 = ".cerber" nocase
        $e5 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $e6 = "HOW_TO_DECRYPT" nocase
        $e7 = "RECOVER_FILES" nocase
    condition:
        any of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon traffic patterns"
        mitre = "T1071.001"
        severity = "CRITICAL"
    strings:
        $c1 = "Content-Type: application/octet-stream" nocase
        $c2 = "MSSE-" nocase
        $c3 = "Referrer:" nocase
        $h  = /\/[a-zA-Z0-9]{4,8}(\.gif|\.png|\.jpg|\.css|\.js)$/
    condition:
        2 of them
}

rule XMRig_Miner {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        mitre = "T1496"
        severity = "HIGH"
    strings:
        $s1 = "xmrig" nocase
        $s2 = "stratum+tcp://" nocase
        $s3 = "monero" nocase
        $s4 = "cryptonight" nocase
        $s5 = "pool.minexmr.com" nocase
    condition:
        any of them
}

rule Nmap_Scan_Signature {
    meta:
        description = "Detects Nmap scanning tool signature in traffic"
        mitre = "T1046"
        severity = "MEDIUM"
    strings:
        $s1 = "Nmap" nocase
        $s2 = "nmap.org" nocase
        $s3 = "NMAP_MAGIC" nocase
        $ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine" nocase
    condition:
        any of them
}

rule Log4Shell_Exploit {
    meta:
        description = "Detects Log4Shell (CVE-2021-44228) exploitation attempts"
        mitre = "T1190"
        severity = "CRITICAL"
    strings:
        $j1 = "${jndi:ldap://" nocase
        $j2 = "${jndi:rmi://" nocase
        $j3 = "${jndi:dns://" nocase
        $j4 = "${${lower:j}ndi" nocase
        $j5 = "${${::-j}${::-n}${::-d}${::-i}" nocase
    condition:
        any of them
}

rule ShellShock_Exploit {
    meta:
        description = "Detects ShellShock (CVE-2014-6271) exploitation in HTTP headers"
        mitre = "T1190"
        severity = "CRITICAL"
    strings:
        $s1 = "() { :; };" nocase
        $s2 = "() { ignored; };" nocase
    condition:
        any of them
}

rule Data_Exfil_Base64_Large {
    meta:
        description = "Large Base64 encoded data in outbound HTTP possibly exfiltration"
        mitre = "T1041"
        severity = "HIGH"
    strings:
        $b64 = /[A-Za-z0-9+\/]{500,}={0,2}/
        $post = "POST" nocase
    condition:
        $post and $b64
}

rule Suspicious_User_Agent {
    meta:
        description = "Known malicious or suspicious HTTP User-Agent strings"
        mitre = "T1071.001"
        severity = "MEDIUM"
    strings:
        $ua1 = "masscan" nocase
        $ua2 = "zgrab" nocase
        $ua3 = "sqlmap" nocase
        $ua4 = "nikto" nocase
        $ua5 = "dirbuster" nocase
        $ua6 = "python-requests" nocase
        $ua7 = "Go-http-client" nocase
        $ua8 = "curl/" nocase
        $ua9 = "Wget/" nocase
    condition:
        any of ($ua1, $ua2, $ua3, $ua4, $ua5) or (2 of ($ua6, $ua7, $ua8, $ua9))
}

rule Credential_Stuffing_Pattern {
    meta:
        description = "Detects credential stuffing patterns in HTTP POST data"
        mitre = "T1110.004"
        severity = "HIGH"
    strings:
        $p1 = "username=" nocase
        $p2 = "password=" nocase
        $p3 = "login=" nocase
        $p4 = "POST /login" nocase
        $p5 = "POST /auth" nocase
    condition:
        ($p1 or $p3) and $p2 and ($p4 or $p5)
}
