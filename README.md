# Automated Brute-Force & Failed Login Detector

Hey there!

This is a lightweight security automation script I built in Python to help analyze server authentication logs and detect potential brute-force or credential-stuffing attacks.

---

### Why I Built This

When monitoring systems as an analyst, checking authentication logs manually line by line is slow and impractical. A common pattern in brute-force attacks is a single IP address generating dozens of failed login attempts in a short timeframe across different accounts (like `admin`, `root`, or standard users).

I wanted to build a simple, reliable script that could ingest raw log files, tally up failed attempts per IP address, and flag anything crossing a suspicious threshold so an analyst can investigate or block the IP immediately.

---

### How It Works

1. **Ingests Log Data:** Uses Python's `with open()` context manager to safely open and read raw server log files without leaving open file descriptors.
2. **Normalizes & Parses:** Cleans whitespace and splits the data line by line using `.splitlines()` (which avoids platform-specific line-ending bugs between Windows and Linux).
3. **Identifies Failed Events:** Loops through each line, splits the string into structured tokens (`[TIMESTAMP]`, `[STATUS]`, `[USER]`, `[IP]`), and isolates events marked as `FAILED`.
4. **Tracks Thresholds:** Uses a dictionary counter to sum up failed attempts per source IP address. If an IP hits or exceeds the threshold (set to 3 by default), it gets flagged.
5. **Generates an Alert Report:** Writes an actionable incident summary to `security_incident_report.txt` listing the suspicious IPs and their exact attempt counts.

---
