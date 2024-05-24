#!/usr/bin/env python3
import re
import subprocess
import argparse
from collections import defaultdict
from typing import Literal

# Sample log entry: '138.68.249.116 - - [13/May/2024:01:21:15 +0100] "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1" 400 150 "-" "-"'
access_log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.+?)\] "(?P<method>\w+) (?P<path>.+?) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"')

# Sample log entry pattern for Nginx error logs
error_log_pattern = re.compile(r'(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[.*?\] (?P<level>\w+) \d+#\d+: \*(?P<id>\d+) (?P<message>.*?), client: (?P<ip>\d+\.\d+\.\d+\.\d+), server: (?P<server>.*?), request: "(?P<method>\w+) (?P<path>.+?) HTTP/\d\.\d", host: "(?P<host>.*?)"')

# List of allowed patterns
allowed_patterns = [
    r'/static/styles/', r'/static/scripts/', r'/static/favicon', r'/login', r'/logout', r'/upload_csv',
    r'/edit_password', r'/add_password', r"/static/hill_logo_blk_vig", r"/authenticate",
    r"/keyexchange", r"/secretprocessing", r"/dashboard", r"/get_user_edek_iv", r"/retrieve_passwords",
    r"/backup", r'/notifications/hub?access_token'
]

# Function to parse the log file and identify suspicious activities
def parse_logs(log_file, log_type: Literal['access', 'error'], verbose=False):
    suspicious_activity = defaultdict(list)
    with open(log_file, 'r') as file:
        for line in file:
            if log_type == 'access':
                match = access_log_pattern.match(line)
            elif log_type == 'error':
                match = error_log_pattern.match(line)
            else:
                continue
            
            if match:
                log_data = match.groupdict()
                ip = log_data['ip']
                date = log_data['date']
                method = log_data['method']
                path = log_data['path']

                # Check for allowed patterns first
                is_allowed = any(re.search(pattern, path) for pattern in allowed_patterns)
                if is_allowed:
                    if verbose:
                        print(f"Allowed request from IP {ip}: {path}")
                    continue

                if log_type == 'access':
                    status = log_data['status']
                    if int(status) > 300:
                        user_agent = log_data['user_agent']
                        suspicious_activity[ip].append({
                            'date': date,
                            'method': method,
                            'path': path,
                            'status': status,
                            'user_agent': user_agent
                        })
                    else:
                        if verbose:
                            print(f"Allowed request from IP {ip}: {path}")
                            continue
                elif log_type == 'error':
                    suspicious_activity[ip].append({
                        'date': date,
                        'method': method,
                        'path': path
                    })
                if verbose:
                    print(f"Matched suspicious pattern from IP {ip}: {path}")
                    #break
    return suspicious_activity

# Generate a report of suspicious activities
def generate_report(suspicious_activity):
    report_lines = []
    for ip, activities in suspicious_activity.items():
        report_lines.append(f"Suspicious activity from IP: {ip}")
        for activity in activities:
            report_line = f"  - Date: {activity['date']}, Method: {activity['method']}, Path: {activity['path']}"
            if 'status' in activity:
                report_line += f", Status: {activity['status']}"
            if 'user_agent' in activity:
                report_line += f", User-Agent: {activity['user_agent']}"
            report_lines.append(report_line)
    return "\n".join(report_lines)

# Function to run ipset commands to block suspicious IPs with timeout
def run_ipset_commands(suspicious_activity, ipset_name="suspicious_ips", timeout=3600, verbose=False):
    # Check if the ipset already exists
    result = subprocess.run(f"sudo ipset list {ipset_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    iptables_result = subprocess.run(f"sudo iptables -vL | grep {ipset_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 1:
        # Create the ipset if it doesn't exist
        subprocess.run(f"sudo ipset create {ipset_name} hash:ip timeout {timeout}", shell=True, check=True)
        if verbose:
            print(f"IPSet '{ipset_name}' created with timeout {timeout} seconds.")
    else:
        existing_ips = result.stdout.decode()
    if iptables_result.returncode == 1:
        subprocess.run(f"sudo  iptables -I INPUT -m set --match-set {ipset_name} src -j DROP", shell=True, check=True)
        # subprocess.run(f"sudo  iptables -I INPUT -m set --match-set myset src -j DROP", shell=True, check=True) # this is personal for abuse ip db
        if verbose:
            print(f"IPSet '{ipset_name}' added to iptables")
    else:
        if verbose:
            print(f"IPSet '{ipset_name}' already exists in iptables")



    ips_added = 0
    for ip in suspicious_activity.keys():
        if ip in existing_ips:
            continue
        subprocess.run(f"sudo ipset add {ipset_name} {ip} timeout {timeout}", shell=True, check=True)
        ips_added += 1
        if verbose:
            print(f"Added IP {ip} to IPSet '{ipset_name}' with timeout {timeout} seconds.")

    if verbose:
        if ips_added > 0:
            print(f"Added {ips_added} IP(s) to IPSet '{ipset_name}'.")
        else:
            print("No IPs to add to IPSet.")

# Function to delete IPs from the IPSet
def delete_ips_from_ipset(ips_to_delete, ipset_name="suspicious_ips", verbose=False):
    ips_deleted = 0
    for ip in ips_to_delete:
        result = subprocess.run(f"sudo ipset del {ipset_name} {ip}", shell=True, stderr=subprocess.PIPE)
        if result.returncode == 0:
            ips_deleted += 1
            if verbose:
                print(f"Deleted IP {ip} from IPSet '{ipset_name}'.")
        else:
            if verbose:
                print(f"Failed to delete IP {ip} from IPSet '{ipset_name}'.")
    
    if verbose:
        if ips_deleted > 0:
            print(f"Deleted {ips_deleted} IP(s) from IPSet '{ipset_name}'.")
        else:
            print("No IPs to delete from IPSet.")

# Main function to run the script
def main():
    parser = argparse.ArgumentParser(description="Parse Nginx logs and manage IPSet.")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable verbose output")
    parser.add_argument('--delete', '-d', nargs='*', help="Delete specified IPs from IPSet")
    args = parser.parse_args()
    
    verbose = args.verbose

    if args.delete:
        delete_ips_from_ipset(args.delete, verbose=verbose)
    else:
        # Parse access log
        access_log_file = '/var/log/nginx/access.log'  # Replace with the path to your access log file
        suspicious_activity_access = parse_logs(access_log_file, log_type='access', verbose=verbose)
        report_access = generate_report(suspicious_activity_access)
        if verbose:
            print(report_access)
        run_ipset_commands(suspicious_activity_access, verbose=verbose)

        # Parse error log
        error_log_file = '/var/log/nginx/error.log'  # Replace with the path to your error log file
        suspicious_activity_error = parse_logs(error_log_file, log_type='error', verbose=verbose)
        report_error = generate_report(suspicious_activity_error)
        if verbose:
            print(report_error)
        run_ipset_commands(suspicious_activity_error, verbose=verbose)

if __name__ == "__main__":
    main()