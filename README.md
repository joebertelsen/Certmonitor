# Certmonitor
TLS Cert Monitor that checks certificates using the java.security package.

# Usage
Certmonitor is a CLI tool that can be used against a 'hosts.txt' file to view the concurrency of active or expiring certificates for the hosts specified

Run:  
java CertMonitor.java hosts.txt [--warn 30] [--crit 14] [--timeout 5000] [--csv report.csv]
Output:
Exit code: 0 = all OK, 1 = at least one expired/expiring/misconfigured/unreachable target.

#Note
 * Note: this tool inspects certificates on hosts you are authorized to test. Use it on
   your own or your client's assets only.
