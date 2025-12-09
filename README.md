


_______________

🛡️ Ultimate Android Hardener — Full Description

Purpose:
This script is a read-only, non-destructive Android security scanner designed to inspect your device for suspicious files, binaries, APKs, processes, network activity, and potential indicators of compromise (IoCs). It helps detect potential backdoors, keyloggers, malware, and misconfigurations that could compromise device security or privacy. It does not delete or modify anything; it only scans and reports.


_______________

Key Features

1. Deep Filesystem Scanning

Scans important system directories like /system, /vendor, /data, /cache, /sdcard, /storage, and more.

Looks for suspicious binaries, shared libraries (*.so), APKs, JARs, DEX files, and hidden files (starting with a dot).

Identifies world-writable files and directories (777) which could be exploited by malware.

Detects SUID/SGID binaries, which can escalate privileges if compromised.



2. Suspicious Binary Detection

Checks for binaries commonly associated with rooting, malware, or hacking frameworks:

su, magisk, supersu, busybox, frida, xposed, riru, titanium, etc.


Scans filenames for keylogger or monitoring indicators (like keylog, hook, monitor, spy).



3. Process Inspection

Reads running processes from /proc.

Flags processes whose command lines or executables match suspicious patterns (rooting/malware tools).



4. SELinux Status Check

Reads /sys/fs/selinux/enforce and runs getenforce.

Provides a quick view of device security mode (enforcing, permissive, disabled).



5. Network & Firewall Checks

Captures listening TCP/UDP ports from /proc/net/tcp and /proc/net/udp.

Lists UNIX sockets from /proc/net/unix.

Reads firewall rules via iptables-save and nft list ruleset.

Helps detect unexpected listening services or open ports that could indicate malware or backdoors.



6. Keylogger / Spy Detection

Scans filenames and directories for keylogger-like names.

Heuristically detects suspicious monitoring tools on device storage.



7. Sensitive File Detection

Searches for files containing credential-like names, such as passwd, shadow, id_rsa, .pem, .key, credentials.

Scans APKs for risky permissions or strings such as:

android.permission.READ_SMS

android.permission.SYSTEM_ALERT_WINDOW

su, magisk, frida, hook, keylog, URLs (http://, https://)




8. LD_PRELOAD / Environment Check

Inspects /etc/ld.so.preload and /proc/*/environ for suspicious environment variables (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT) that malware may use for hooking or injecting code.



9. Common Rooting Detection

Checks for su binaries and Magisk directories in common locations (/system/bin/su, /data/adb/magisk, /cache/magisk).



10. Init Scripts Scan

Inspects init and init.d directories for scripts that may automatically launch suspicious services on boot.



11. World-Writable & 777 Detection

Detects files and directories writable by everyone (potential attack vector).



12. SUID/SGID Binary Detection

Finds binaries with elevated privileges that can be exploited if compromised.



13. APK Risk Scanning

Reads APK file bytes (best-effort) to detect:

Dangerous permissions

Embedded URLs, hooks, or known malware indicators




14. Baseline Comparison

Save a snapshot of your system state to compare with later scans.

Detects changes such as new suspicious files, modified files, or missing files.



15. Configurable Scan Depth

--fast: quicker scan, skips very deep filesystem traversal.

--deep: more thorough, scans more files and directories.

Works even without root, but root access gives full coverage.



16. Emoji-Enhanced Human Report

⚠️ Suspicious binaries

🛠️ Root-related files (su, Magisk)

🕵️ Keylogger indicators

🔐 SELinux status

🌐 Network-related findings

🔑 Credential-like files

📦 APK files

🔓 World-writable files

🔌 Open sockets


Example report snippet:

🕵️ Keylogger/spy indicators (names): 5
  - /data/local/tmp/keylog.apk 🕵️
  - /sdcard/Download/spytool.so 🕵️
⚠️ Suspicious binaries found: 3
  - /system/xbin/su 🛠️
  - /data/local/tmp/frida-server ⚠️


17. Output Options

JSON output: save full structured scan results to a file.

Baseline snapshot: compare changes over time.

Human-readable console report with emojis.





_______________

Summary of What It Protects Against

Category	Protection / Detection

Rooting / Magisk / SU	Detects binaries and directories commonly used for rooting.
Malware & Spyware	Detects suspicious binaries, keyloggers, injected processes, APKs with risky strings.
Credential Theft	Finds files that may contain passwords, keys, or credentials.
Network Exposure	Lists listening sockets and firewall rules to detect backdoors or exfiltration points.
Privilege Escalation	Flags SUID/SGID binaries and world-writable files.
Hooking & Injection	LD_PRELOAD, environment variables, init scripts, and APK hooks are scanned.
File Changes	Baseline comparison detects added, removed, or modified files.
Heuristic Indicators	Uses patterns, names, and common malware indicators to flag potential threats.



_______________

Safety Notes

Read-only: does not delete, modify, or execute suspicious files.

Heuristic detection: flagged items are indicators, not confirmed malware.

Root recommended: for full scan of /data and protected paths.

Can be safely run multiple times to monitor changes over time.



_______________

In short, this script is like having a full forensic scanner and security auditor for your Android device, reporting potential security risks, suspicious binaries, hidden keyloggers, credential leaks, and network exposures, all in a single comprehensive read-only scan.


