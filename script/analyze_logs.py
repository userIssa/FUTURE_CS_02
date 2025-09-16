#!/usr/bin/env python3
"""
analyze_logs.py
SOC Log Analyzer - parses SOC_Task2_Sample_Logs.txt style logs, identifies suspicious alerts,
classifies incidents, exports timeline CSV, incidents JSON, a markdown incident report, 
an email template, and generates visualization charts.

Usage:
    python3 analyze_logs.py /path/to/SOC_Task2_Sample_Logs.txt
"""

import sys
import re
import csv
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dateutil import parser as dtparser
from pathlib import Path
import matplotlib.pyplot as plt

# -------------------
# Configurations
# -------------------
LOG_PATTERN = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| user=(?P<user>[^ ]+) \| ip=(?P<ip>[^ ]+) \| action=(?P<action>[^|]+)(?: \| threat=(?P<threat>.+))?'
)

HIGH_MALWARE_TAGS = {'ransomware behavior', 'rootkit signature', 'spyware alert'}
MEDIUM_MALWARE_TAGS = {'trojan detected', 'worm infection attempt'}

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 30
MULTI_IP_WINDOW_MINUTES = 60


# -------------------
# Log Parsing
# -------------------
def parse_log_line(line):
    m = LOG_PATTERN.search(line.strip())
    if not m:
        return None
    d = m.groupdict()
    ts = dtparser.parse(d['ts'])
    return {
        'ts': ts,
        'user': d['user'],
        'ip': d['ip'],
        'action': d['action'].strip(),
        'threat': (d.get('threat') or '').strip()
    }


def load_logs(path):
    entries = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            p = parse_log_line(line)
            if p:
                entries.append(p)
    return sorted(entries, key=lambda x: x['ts'])


# -------------------
# Detection Functions
# -------------------
def detect_malware_incidents(entries):
    incidents = []
    for e in entries:
        if 'malware detected' in e['action'].lower() or e['threat']:
            thr = e['threat']
            sev = 'Medium'
            if thr.lower() in HIGH_MALWARE_TAGS:
                sev = 'High'
            elif thr.lower() in MEDIUM_MALWARE_TAGS:
                sev = 'High'
            incidents.append({
                'type': 'malware',
                'user': e['user'],
                'ip': e['ip'],
                'timestamp': e['ts'].isoformat(),
                'threat': thr or 'Unknown Malware',
                'severity': sev
            })
    return incidents


def detect_failed_logins(entries):
    user_fail_times = defaultdict(list)
    for e in entries:
        if 'login failed' in e['action'].lower():
            user_fail_times[e['user']].append(e['ts'])

    suspicious = []
    for user, times in user_fail_times.items():
        times.sort()
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES):
                i += 1
            count = j - i + 1
            if count >= FAILED_LOGIN_THRESHOLD:
                suspicious.append({
                    'type': 'failed_logins',
                    'user': user,
                    'count': count,
                    'window_minutes': FAILED_LOGIN_WINDOW_MINUTES,
                    'first': times[i].isoformat(),
                    'last': times[j].isoformat(),
                    'severity': 'Medium'
                })
    return suspicious


def detect_multi_ip_logins(entries):
    user_login_events = defaultdict(list)
    for e in entries:
        if 'login success' in e['action'].lower():
            user_login_events[e['user']].append((e['ts'], e['ip']))

    suspicious = []
    for user, events in user_login_events.items():
        events.sort()
        for i in range(len(events)):
            ips = {events[i][1]}
            endtime = events[i][0] + timedelta(minutes=MULTI_IP_WINDOW_MINUTES)
            for j in range(i + 1, len(events)):
                if events[j][0] <= endtime:
                    ips.add(events[j][1])
            if len(ips) >= 2:
                suspicious.append({
                    'type': 'multi_ip_login',
                    'user': user,
                    'ips': list(ips),
                    'start': events[i][0].isoformat(),
                    'end': endtime.isoformat(),
                    'severity': 'Medium' if len(ips) < 4 else 'High'
                })
    return suspicious


def find_file_access_after_malware(entries, malware_incidents):
    suspicious_followups = []
    for m in malware_incidents:
        m_ts = dtparser.parse(m['timestamp'])
        for e in entries:
            if e['user'] == m['user'] and e['ip'] == m['ip'] and 'file accessed' in e['action'].lower():
                if 0 <= (e['ts'] - m_ts).total_seconds() <= 3600:
                    suspicious_followups.append({
                        'type': 'file_access_post_malware',
                        'user': e['user'],
                        'ip': e['ip'],
                        'malware_ts': m_ts.isoformat(),
                        'file_access_ts': e['ts'].isoformat(),
                        'severity': 'High'
                    })
    return suspicious_followups


# -------------------
# Reporting
# -------------------
def build_timeline_csv(entries, out_path):
    with open(out_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['timestamp', 'user', 'ip', 'action', 'threat'])
        for e in entries:
            writer.writerow([e['ts'].isoformat(), e['user'], e['ip'], e['action'], e.get('threat', '')])


def summarize_incidents(malware, failed_logins, multi_ip, followups):
    incidents = malware + failed_logins + multi_ip + followups
    users_with_malware = {m['user'] for m in malware}
    if len(users_with_malware) >= 2:
        incidents.append({
            'type': 'widespread_malware_pattern',
            'users_affected': list(users_with_malware),
            'severity': 'High',
            'note': 'Multiple users triggered malware detections - possible lateral spread.'
        })
    return incidents


def generate_markdown_report(incidents, timeline_file, out_path):
    now = datetime.utcnow().isoformat() + 'Z'
    lines = [
        f"# Incident Response Report (automated)\nGenerated: {now}\n",
        "## Executive Summary\nAutomated monitoring detected malware alerts and suspicious authentication patterns.\n",
        "## Affected Entities\n- Timeline file: " + timeline_file + "\n",
        "## Incident Summary\n"
    ]
    for idx, inc in enumerate(incidents, 1):
        lines.append(f"### Incident {idx}\n```json\n{json.dumps(inc, indent=2)}\n```\n")
    lines.append("## Recommended Actions\n- Isolate hosts\n- Reset credentials\n- Run AV/EDR scans\n- Block malicious IPs\n")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    return out_path


def generate_email_template(incidents, out_path):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    subj = "Security Incident Notification - Action Required"
    body = [
        f"Subject: {subj}",
        "To: IT Security Management",
        "From: SOC Analyst (Automated Report)",
        f"Date: {now}\n",
        "Summary:\nMultiple malware and suspicious authentication events detected.",
        "\nKey Findings:"
    ]
    for inc in incidents[:8]:
        brief = inc.get('type', '') + " - " + (inc.get('user') or ','.join(inc.get('users_affected', [])))
        if inc.get('threat'):
            brief += f" ({inc['threat']})"
        brief += f" | severity: {inc.get('severity', 'Unknown')}"
        body.append("- " + brief)
    body.append("\nActions: Isolate hosts, reset creds, run scans.")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(body))
    return out_path


# -------------------
# Visualization
# -------------------
def generate_visualizations(entries, out_dir="charts"):
    os.makedirs(out_dir, exist_ok=True)

    # Malware detections over time
    malware_counts = Counter([e['ts'].date() for e in entries if 'malware detected' in e['action'].lower()])
    if malware_counts:
        plt.figure()
        dates, counts = zip(*sorted(malware_counts.items()))
        plt.plot(dates, counts, marker='o')
        plt.title("Malware Detections Over Time")
        plt.xlabel("Date")
        plt.ylabel("Detections")
        plt.savefig(os.path.join(out_dir, "malware_over_time.png"))

    # Threat type distribution
    threats = [e['threat'] for e in entries if e['threat']]
    if threats:
        plt.figure()
        counts = Counter(threats)
        plt.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%')
        plt.title("Threat Type Distribution")
        plt.savefig(os.path.join(out_dir, "threat_distribution.png"))

    # Failed logins by user
    failed_users = Counter([e['user'] for e in entries if 'login failed' in e['action'].lower()])
    if failed_users:
        plt.figure()
        plt.bar(failed_users.keys(), failed_users.values())
        plt.title("Failed Logins by User")
        plt.xlabel("User")
        plt.ylabel("Failed Logins")
        plt.savefig(os.path.join(out_dir, "failed_logins_by_user.png"))

    # Actions over time
    plt.figure()
    action_counts = Counter([e['action'] for e in entries])
    plt.bar(action_counts.keys(), action_counts.values())
    plt.title("Overall Action Distribution")
    plt.xticks(rotation=45, ha='right')
    plt.savefig(os.path.join(out_dir, "action_distribution.png"))


# -------------------
# Main
# -------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_logs.py /path/to/logfile")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print("File not found:", path)
        sys.exit(1)

    entries = load_logs(path)
    if not entries:
        print("No parsable log lines found.")
        sys.exit(1)

    # Outputs
    timeline_file = 'timeline.csv'
    build_timeline_csv(entries, timeline_file)

    malware = detect_malware_incidents(entries)
    failed_logins = detect_failed_logins(entries)
    multi_ip = detect_multi_ip_logins(entries)
    followups = find_file_access_after_malware(entries, malware)
    incidents = summarize_incidents(malware, failed_logins, multi_ip, followups)

    with open('incidents.json', 'w', encoding='utf-8') as f:
        json.dump(incidents, f, indent=2)

    report_path = generate_markdown_report(incidents, timeline_file, 'report.md')
    email_path = generate_email_template(incidents, 'email.txt')
    generate_visualizations(entries)

    print("Done. Generated files:")
    print(" -", Path.cwd() / timeline_file)
    print(" -", Path.cwd() / 'incidents.json')
    print(" -", Path.cwd() / report_path)
    print(" -", Path.cwd() / email_path)
    print(" - Charts saved in ./charts/")


if __name__ == '__main__':
    main()
