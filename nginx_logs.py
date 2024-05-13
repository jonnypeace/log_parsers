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

# List of suspicious patterns (expanded)
suspicious_patterns = [
    r'/cgi-bin/', r'/manager/', r'/owa/', r'/sdk', r'/HNAP1', r'/query', r'/web/', r'/authLogin.cgi', r'/actuator/health',
    r'/v2/_catalog', r'/Res/', r'/sra_', r'/admin/', r'/login', r'/wp-login', r'/wp-admin', r'/xmlrpc.php', r'/shell',
    r'/debug', r'/console', r'/portal', r'/config', r'/config.json', r'/setup', r'/setup.php', r'/install', r'/install.php',
    r'/robots.txt', r'/sitemap.xml', r'/phpmyadmin', r'/pma', r'/sql', r'/database', r'/dump', r'/backup', r'/bak', r'/test',
    r'/examples', r'/temp', r'/tmp', r'/old', r'/wordpress', r'/joomla', r'/drupal', r'/user', r'/users', r'/account',
    r'/accounts', r'/signin', r'/signup', r'/register', r'/password', r'/passwd', r'/data', r'/scripts', r'/cmd',
    r'/command', r'/bin', r'/exec', r'/runtime', r'/api', r'/rpc', r'/service', r'/services', r'/file', r'/files',
    r'/upload', r'/uploads', r'/download', r'/downloads', r'/private', r'/secure', r'/security', r'/report', r'/reports',
    r'/log', r'/logs', r'/error', r'/errors', r'/system', r'/root', r'/session', r'/sessions', r'/token', r'/tokens',
    r'/credentials', r'/secret', r'/secrets', r'/key', r'/keys', r'/privatekey', r'/privatekeys', r'/publickey', r'/publickeys',
    r'/access', r'/access.log', r'/error.log', r'/phpinfo', r'/server-status', r'/info', r'/status', r'/version', r'/versions',
    r'/license', r'/licenses', r'/license.txt', r'/readme', r'/readme.txt', r'/readme.html', r'/readme.md', r'/CHANGELOG',
    r'/CHANGELOG.txt', r'/changelog', r'/changelog.txt', r'/CHANGELOG.md', r'/changelog.md', r'/help', r'/docs',
    r'/documentation', r'/manual', r'/guide', r'/guides', r'/tutorial', r'/tutorials', r'/examples', r'/sample', r'/samples',
    r'/demo', r'/demos', r'/test', r'/tests', r'/testing', r'/example', r'/examples', r'/samples', r'/template',
    r'/templates', r'/image', r'/images', r'/img', r'/imgs', r'/css', r'/styles', r'/style', r'/stylesheets', r'/stylesheet',
    r'/js', r'/javascript', r'/scripts', r'/assets', r'/asset', r'/font', r'/fonts', r'/webfonts', r'/webfont', r'/icon',
    r'/icons', r'/favicon', r'/favicons', r'/media', r'/medias', r'/video', r'/videos', r'/audio', r'/audios', r'/sound',
    r'/sounds', r'/music', r'/musics', r'/archive', r'/archives', r'/zip', r'/zips', r'/tar', r'/tars', r'/rar', r'/rars',
    r'/7z', r'/7zip', r'/gzip', r'/gz', r'/gzip', r'/bzip', r'/bz2', r'/xz', r'/zst', r'/tar.gz', r'/tar.xz', r'/tar.bz2',
    r'/tar.zst', r'/api/v1', r'/api/v2', r'/api/v3', r'/api/v4', r'/api/v5', r'/api/v6', r'/api/v7', r'/api/v8', r'/api/v9',
    r'/api/v10', r'/public/api', r'/internal/api', r'/external/api', r'/private/api', r'/external/private/api', r'/ws',
    r'/websocket', r'/ws/', r'/ws/private', r'/ws/public', r'/ws/internal', r'/ws/external', r'/ws/admin', r'/ws/user',
    r'/ws/account', r'/ws/service', r'/ws/file', r'/ws/files', r'/ws/download', r'/ws/upload', r'/ws/security', r'/ws/access',
    r'/ws/token', r'/ws/tokens', r'/ws/secret', r'/ws/secrets', r'/ws/key', r'/ws/keys', r'/ws/license', r'/ws/licenses',
    r'/ws/status', r'/ws/version', r'/ws/info', r'/ws/help', r'/ws/docs', r'/ws/documentation', r'/ws/manual', r'/ws/guide',
    r'/ws/guides', r'/ws/tutorial', r'/ws/tutorials', r'/ws/examples', r'/ws/sample', r'/ws/samples', r'/ws/demo', r'/ws/demos',
    r'/ws/test', r'/ws/tests', r'/ws/testing', r'/ws/example', r'/ws/examples', r'/ws/samples', r'/ws/template', r'/ws/templates',
    r'/ws/image', r'/ws/images', r'/ws/img', r'/ws/imgs', r'/ws/css', r'/ws/styles', r'/ws/style', r'/ws/stylesheets',
    r'/ws/stylesheet', r'/ws/js', r'/ws/javascript', r'/ws/scripts', r'/ws/assets', r'/ws/asset', r'/ws/font', r'/ws/fonts',
    r'/ws/webfonts', r'/ws/webfont', r'/ws/icon', r'/ws/icons', r'/ws/favicon', r'/ws/favicons', r'/ws/media', r'/ws/medias',
    r'/ws/video', r'/ws/videos', r'/ws/audio', r'/ws/audios', r'/ws/sound', r'/ws/sounds', r'/ws/music', r'/ws/musics',
    r'/ws/archive', r'/ws/archives', r'/ws/zip', r'/ws/zips', r'/ws/tar', r'/ws/tars', r'/ws/rar', r'/ws/rars', r'/ws/7z',
    r'/ws/7zip', r'/ws/gzip', r'/ws/gz', r'/ws/gzip', r'/ws/bzip', r'/ws/bz2', r'/ws/xz', r'/ws/zst', r'/ws/tar.gz', r'/ws/tar.xz',
    r'/ws/tar.bz2', r'/ws/tar.zst',
]

# List of allowed patterns
allowed_patterns = [
    r'/static/styles/', r'/static/scripts/', r'/static/favicon.ico', r'/keyexchange', r'/secretprocessing', r'/login'
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

                # Check for suspicious patterns in the path
                for pattern in suspicious_patterns:
                    if re.search(pattern, path):
                        if log_type == 'access':
                            status = log_data['status']
                            user_agent = log_data['user_agent']
                            suspicious_activity[ip].append({
                                'date': date,
                                'method': method,
                                'path': path,
                                'status': status,
                                'user_agent': user_agent
                            })
                        elif log_type == 'error':
                            suspicious_activity[ip].append({
                                'date': date,
                                'method': method,
                                'path': path
                            })
                        if verbose:
                            print(f"Matched suspicious pattern from IP {ip}: {path}")
                        break
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
    if result.returncode == 1:
        # Create the ipset if it doesn't exist
        subprocess.run(f"sudo ipset create {ipset_name} hash:ip timeout {timeout}", shell=True, check=True)
        if verbose:
            print(f"IPSet '{ipset_name}' created with timeout {timeout} seconds.")
    else:
        existing_ips = result.stdout.decode()

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
