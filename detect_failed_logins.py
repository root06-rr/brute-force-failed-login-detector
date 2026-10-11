"""
Project: Automated Brute-Force & Failed Login Detection Engine
Description: Parses server authentication logs, counts consecutive failed 
             login attempts per IP/user using Python file-handling and lists, 
             and exports an alert report for addresses exceeding the threshold.
"""

def parse_auth_log(log_filepath):
    """
    Reads an authentication log and extracts structured log lines.
    Demonstrates file handling and string-to-list splitting.
    """
    with open(log_filepath, "r") as file:
        raw_data = file.read()
    
    # Split the multi-line log string into individual events
    log_lines = raw_data.split("\n")
    return log_lines


def analyze_failed_attempts(log_lines, threshold=3):
    """
    Iterates through log entries, isolates failed attempts, 
    and detects source IPs exceeding the failure threshold.
    """
    failed_counts = {}
    flagged_ips = []

    for line in log_lines:
        # Ignore empty lines
        if not line.strip():
            continue
        
        # Log structure: [TIMESTAMP] [STATUS] [USER] [IP]
        parts = line.split()
        
        if len(parts) >= 4:
            status = parts[1]
            ip_address = parts[3]

            if status == "FAILED":
                if ip_address in failed_counts:
                    failed_counts[ip_address] += 1
                else:
                    failed_counts[ip_address] = 1

    # Check for threshold breaches
    for ip, count in failed_counts.items():
        if count >= threshold:
            flagged_ips.append(ip)

    return failed_counts, flagged_ips


def write_alert_report(report_filepath, flagged_ips, failed_counts):
    """
    Writes a security incident summary file containing flagged IPs.
    """
    with open(report_filepath, "w") as report_file:
        report_file.write("=== SECURITY ALERT: FAILED LOGIN AUDIT REPORT ===\n")
        report_file.write(f"Flagged Suspicious IP Addresses: {len(flagged_ips)}\n")
        report_file.write("-" * 50 + "\n\n")

        if flagged_ips:
            for ip in flagged_ips:
                count = failed_counts[ip]
                report_file.write(f"[ALERT] IP: {ip} | Failed Attempts: {count}\n")
        else:
            report_file.write("No anomalous activity detected.\n")


if __name__ == "__main__":
    LOG_FILE = "auth_events.log"
    REPORT_FILE = "security_incident_report.txt"
    FAILED_LOGIN_THRESHOLD = 3

    print("[*] Ingesting authentication events...")
    entries = parse_auth_log(LOG_FILE)

    print("[*] Auditing failed authentication attempts...")
    counts, flagged = analyze_failed_attempts(entries, threshold=FAILED_LOGIN_THRESHOLD)

    print(f"[!] Total suspicious IPs detected: {len(flagged)}")
    write_alert_report(REPORT_FILE, flagged, counts)
    print(f"[+] Incident report generated: {REPORT_FILE}")