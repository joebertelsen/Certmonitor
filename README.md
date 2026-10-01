# Certmonitor
TLS Cert Monitor that checks certificates using the java.security package.

# Usage
Certmonitor is a CLI tool that reads against a 'hosts.txt' file to view the concurrency of active or expiring certificates for the hosts specified

Run:  

`java CertMonitor.java hosts.txt [--warn 30] [--crit 14] [--timeout 5000] [--csv report.csv]` 

Flags:

--warn 30
This sets the "WARNING" threshold in days. A certificate expiring within 30 days (but not within the critical window) gets the status WARNING. The default is 30. Use a larger number if your renewal process is slow, such as 60 or 90 when renewals need approvals.

--crit 14
This sets the "CRITICAL" threshold in days. A certificate expiring within 14 days gets CRITICAL. The default is 14. Keep it smaller than --warn. In the code, the critical check runs first, so if you set crit larger than warn, nothing would ever show as WARNING.

--timeout 5000
This is how long, in milliseconds, to wait on the network before giving up on a host. Measured in MS (5000 ms = 5 seconds) It applies both to opening the connection and to waiting for the server's replies during the handshake. A host that exceeds it is reported as ERROR and the scan continues. Raise it for slow or distant servers, and lower it (such as 1500) if you want a fast pass over a large list where dead hosts are common.

--csv report.csv
This writes the results to a CSV file at the path you give, in addition to the console table. It opens in Excel and includes extra columns the table doesn't show (subject, issuer, signature algorithm, TLS version). Without this flag, no file is written. If the file already exists, it's overwritten.

Output: 

Exit code: 0 = all OK, 1 = at least one expired/expiring/misconfigured/unreachable target.

# Note
This tool inspects certificates on hosts you are authorized to test. Use it on your own or your client's assets only.
