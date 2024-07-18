# NIX_Triage.py
# To parse most of Linux and MacOSX artefacts for Incident Response
# Version 0.1
# DFIR Jedi
# 18/07/2024

import os
import re
import json
import csv
import subprocess
import platform
from datetime import datetime
import argparse

# Helper function to save data as JSON
def save_as_json(data, filename):
    with open(f'{filename}.json', 'w') as f:
        json.dump(data, f, indent=4)

# Helper function to save data as CSV
def save_as_csv(data, filename, fieldnames):
    with open(f'{filename}.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

# Parsing functions
def parse_syslog(log_file):
    with open(log_file, 'r') as file:
        logs = file.readlines()
    parsed_logs = []
    for log in logs:
        match = re.match(r'(\w+ \d+ \d+:\d+:\d+) (\w+) (.+)', log)
        if match:
            date, host, message = match.groups()
            parsed_logs.append({'date': date, 'host': host, 'message': message})
    return parsed_logs

def parse_auth_log(log_file):
    with open(log_file, 'r') as file:
        logs = file.readlines()
    parsed_logs = []
    for log in logs:
        match = re.match(r'(\w+ \d+ \d+:\d+:\d+) (\w+) (.+)', log)
        if match:
            date, host, message = match.groups()
            parsed_logs.append({'date': date, 'host': host, 'message': message})
    return parsed_logs

def get_file_metadata(path):
    metadata = os.stat(path)
    return {
        'path': path,
        'size': metadata.st_size,
        'permissions': metadata.st_mode,
        'owner': metadata.st_uid,
        'group': metadata.st_gid,
        'last_accessed': datetime.fromtimestamp(metadata.st_atime).isoformat(),
        'last_modified': datetime.fromtimestamp(metadata.st_mtime).isoformat(),
        'creation_time': datetime.fromtimestamp(metadata.st_ctime).isoformat()
    }

def get_network_connections():
    result = subprocess.run(['netstat', '-tunapl'], capture_output=True, text=True)
    connections = result.stdout.splitlines()
    parsed_connections = []
    for connection in connections:
        if re.match(r'^tcp|udp', connection):
            parts = connection.split()
            parsed_connections.append({
                'protocol': parts[0],
                'local_address': parts[3],
                'foreign_address': parts[4],
                'state': parts[5] if len(parts) > 5 else 'N/A'
            })
    return parsed_connections

def get_installed_packages():
    result = subprocess.run(['dpkg', '--list'], capture_output=True, text=True)
    packages = result.stdout.splitlines()
    parsed_packages = []
    for package in packages:
        match = re.match(r'^ii\s+(\S+)\s+(\S+)\s+(.+)', package)
        if match:
            name, version, description = match.groups()
            parsed_packages.append({'name': name, 'version': version, 'description': description})
    return parsed_packages

def get_scheduled_tasks():
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    tasks = result.stdout.splitlines()
    parsed_tasks = []
    for task in tasks:
        if not task.startswith('#'):
            parsed_tasks.append(task)
    return parsed_tasks

def get_system_info():
    system_info = {
        'os': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }
    return system_info

def get_bash_history(user_home):
    bash_history_path = os.path.join(user_home, '.bash_history')
    if os.path.exists(bash_history_path):
        with open(bash_history_path, 'r') as file:
            history = file.readlines()
        return [{'command': cmd.strip()} for cmd in history]
    return []

def get_recent_files(user_home):
    result = subprocess.run(['find', user_home, '-type', 'f', '-printf', '%T@ %p\n'], capture_output=True, text=True)
    files = result.stdout.splitlines()
    recent_files = sorted(files, reverse=True)[:20]  # Get the 20 most recently accessed files
    parsed_files = [{'timestamp': f.split(' ')[0], 'path': f.split(' ')[1]} for f in recent_files]
    return parsed_files

def get_user_sessions():
    result = subprocess.run(['last'], capture_output=True, text=True)
    sessions = result.stdout.splitlines()
    parsed_sessions = []
    for session in sessions:
        if session:
            parsed_sessions.append({'session': session})
    return parsed_sessions

def get_running_processes():
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    processes = result.stdout.splitlines()
    parsed_processes = []
    for process in processes:
        if process:
            parsed_processes.append({'process': process})
    return parsed_processes

def get_open_files():
    result = subprocess.run(['lsof'], capture_output=True, text=True)
    open_files = result.stdout.splitlines()
    parsed_files = []
    for file in open_files:
        if file:
            parsed_files.append({'file': file})
    return parsed_files

def get_kernel_modules():
    result = subprocess.run(['lsmod'], capture_output=True, text=True)
    modules = result.stdout.splitlines()
    parsed_modules = []
    for module in modules[1:]:  # Skipping the header
        parts = module.split()
        parsed_modules.append({
            'module': parts[0],
            'size': parts[1],
            'used_by': parts[2] if len(parts) > 2 else 'N/A'
        })
    return parsed_modules

def get_mounted_filesystems():
    result = subprocess.run(['mount'], capture_output=True, text=True)
    filesystems = result.stdout.splitlines()
    parsed_filesystems = []
    for fs in filesystems:
        if fs:
            parsed_filesystems.append({'filesystem': fs})
    return parsed_filesystems

def get_systemd_services():
    result = subprocess.run(['systemctl', 'list-units', '--type=service', '--all'], capture_output=True, text=True)
    services = result.stdout.splitlines()
    parsed_services = []
    for service in services:
        if service:
            parsed_services.append({'service': service})
    return parsed_services

def get_environment_variables():
    env_vars = os.environ
    return [{'variable': k, 'value': v} for k, v in env_vars.items()]

def get_user_information():
    result = subprocess.run(['getent', 'passwd'], capture_output=True, text=True)
    users = result.stdout.splitlines()
    parsed_users = []
    for user in users:
        parts = user.split(':')
        parsed_users.append({
            'username': parts[0],
            'password': parts[1],
            'uid': parts[2],
            'gid': parts[3],
            'gecos': parts[4],
            'home_directory': parts[5],
            'shell': parts[6]
        })
    return parsed_users

def get_firewall_rules():
    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
    rules = result.stdout.splitlines()
    parsed_rules = []
    for rule in rules:
        if rule:
            parsed_rules.append({'rule': rule})
    return parsed_rules

def get_listening_ports():
    result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
    ports = result.stdout.splitlines()
    parsed_ports = []
    for port in ports:
        if port:
            parsed_ports.append({'port': port})
    return parsed_ports

def get_ssh_config():
    ssh_config_path = '/etc/ssh/sshd_config'
    if os.path.exists(ssh_config_path):
        with open(ssh_config_path, 'r') as file:
            config = file.readlines()
        return [{'config': line.strip()} for line in config if line.strip()]
    return []

def get_user_groups():
    result = subprocess.run(['getent', 'group'], capture_output=True, text=True)
    groups = result.stdout.splitlines()
    parsed_groups = []
    for group in groups:
        parts = group.split(':')
        parsed_groups.append({
            'group_name': parts[0],
            'password': parts[1],
            'gid': parts[2],
            'members': parts[3].split(',') if parts[3] else []
        })
    return parsed_groups

def get_user_home_directories():
    result = subprocess.run(['ls', '-d', '/home/*'], capture_output=True, text=True)
    home_dirs = result.stdout.splitlines()
    parsed_dirs = [{'directory': d} for d in home_dirs]
    return parsed_dirs

def get_login_failures():
    result = subprocess.run(['grep', 'Failed password', '/var/log/auth.log'], capture_output=True, text=True)
    failures = result.stdout.splitlines()
    parsed_failures = []
    for failure in failures:
        if failure:
            parsed_failures.append({'failure': failure})
    return parsed_failures

def get_system_uptime():
    result = subprocess.run(['uptime', '-p'], capture_output=True, text=True)
    uptime = result.stdout.strip()
    return {'uptime': uptime}

def get_arp_cache():
    result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
    arp_cache = result.stdout.splitlines()
    parsed_cache = []
    for entry in arp_cache:
        if entry:
            parsed_cache.append({'entry': entry})
    return parsed_cache

def get_dns_cache():
    result = subprocess.run(['systemd-resolve', '--statistics'], capture_output=True, text=True)
    dns_cache = result.stdout.splitlines()
    parsed_cache = []
    for entry in dns_cache:
        if entry:
            parsed_cache.append({'entry': entry})
    return parsed_cache

def get_usb_devices():
    result = subprocess.run(['lsusb'], capture_output=True, text=True)
    usb_devices = result.stdout.splitlines()
    parsed_devices = []
    for device in usb_devices:
        if device:
            parsed_devices.append({'device': device})
    return parsed_devices

def get_inode_information(path):
    result = subprocess.run(['ls', '-i', path], capture_output=True, text=True)
    inodes = result.stdout.splitlines()
    parsed_inodes = [{'inode_info': inode} for inode in inodes]
    return parsed_inodes

def get_network_interfaces():
    result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
    interfaces = result.stdout.splitlines()
    parsed_interfaces = [{'interface': interface} for interface in interfaces]
    return parsed_interfaces

def get_boot_logs():
    result = subprocess.run(['journalctl', '-b'], capture_output=True, text=True)
    boot_logs = result.stdout.splitlines()
    parsed_logs = [{'log': log} for log in boot_logs]
    return parsed_logs

def get_memory_usage():
    result = subprocess.run(['free', '-h'], capture_output=True, text=True)
    memory = result.stdout.splitlines()
    parsed_memory = [{'memory_usage': mem} for mem in memory]
    return parsed_memory

def get_disk_usage():
    result = subprocess.run(['df', '-h'], capture_output=True, text=True)
    disk_usage = result.stdout.splitlines()
    parsed_usage = [{'disk_usage': usage} for usage in disk_usage]
    return parsed_usage

def get_sudo_logs():
    result = subprocess.run(['cat', '/var/log/sudo.log'], capture_output=True, text=True)
    sudo_logs = result.stdout.splitlines()
    parsed_logs = [{'log': log} for log in sudo_logs]
    return parsed_logs

def get_docker_containers():
    result = subprocess.run(['docker', 'ps', '--all'], capture_output=True, text=True)
    containers = result.stdout.splitlines()
    parsed_containers = []
    for container in containers:
        if container:
            parsed_containers.append({'container': container})
    return parsed_containers

def get_all_user_crontabs():
    users = [user['username'] for user in get_user_information()]
    crontabs = []
    for user in users:
        result = subprocess.run(['crontab', '-u', user, '-l'], capture_output=True, text=True)
        crontab = result.stdout.splitlines()
        crontabs.append({'user': user, 'crontab': crontab})
    return crontabs

def get_audit_logs():
    result = subprocess.run(['ausearch', '-i'], capture_output=True, text=True)
    audit_logs = result.stdout.splitlines()
    parsed_logs = [{'log': log} for log in audit_logs]
    return parsed_logs

def get_systemd_journal_logs():
    result = subprocess.run(['journalctl'], capture_output=True, text=True)
    journal_logs = result.stdout.splitlines()
    parsed_logs = [{'log': log} for log in journal_logs]
    return parsed_logs

def get_selinux_status():
    result = subprocess.run(['sestatus'], capture_output=True, text=True)
    status = result.stdout.splitlines()
    parsed_status = [{'status': line} for line in status]
    return parsed_status

def get_pam_configuration():
    pam_files = ['/etc/pam.d/common-auth', '/etc/pam.d/common-account', '/etc/pam.d/common-password', '/etc/pam.d/common-session']
    pam_config = []
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            with open(pam_file, 'r') as file:
                config = file.readlines()
            pam_config.append({'file': pam_file, 'config': config})
    return pam_config

def get_kernel_boot_parameters():
    result = subprocess.run(['cat', '/proc/cmdline'], capture_output=True, text=True)
    boot_params = result.stdout.strip()
    return {'boot_parameters': boot_params}

def get_ssh_known_hosts(user_home):
    known_hosts_path = os.path.join(user_home, '.ssh', 'known_hosts')
    if os.path.exists(known_hosts_path):
        with open(known_hosts_path, 'r') as file:
            known_hosts = file.readlines()
        return [{'host': host.strip()} for host in known_hosts]
    return []

def get_installed_python_packages():
    result = subprocess.run(['pip', 'list'], capture_output=True, text=True)
    packages = result.stdout.splitlines()
    parsed_packages = []
    for package in packages:
        if package:
            parsed_packages.append({'package': package})
    return parsed_packages

def get_installed_ruby_gems():
    result = subprocess.run(['gem', 'list'], capture_output=True, text=True)
    gems = result.stdout.splitlines()
    parsed_gems = []
    for gem in gems:
        if gem:
            parsed_gems.append({'gem': gem})
    return parsed_gems

def get_installed_node_packages():
    result = subprocess.run(['npm', 'list', '-g', '--depth=0'], capture_output=True, text=True)
    packages = result.stdout.splitlines()
    parsed_packages = []
    for package in packages:
        if package:
            parsed_packages.append({'package': package})
    return parsed_packages

def get_system_hostname():
    result = subprocess.run(['hostname'], capture_output=True, text=True)
    hostname = result.stdout.strip()
    return {'hostname': hostname}

def get_system_timezone():
    result = subprocess.run(['timedatectl'], capture_output=True, text=True)
    timezone_info = result.stdout.splitlines()
    parsed_info = [{'info': line} for line in timezone_info]
    return parsed_info

def get_active_network_connections():
    result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True)
    connections = result.stdout.splitlines()
    parsed_connections = []
    for connection in connections:
        if connection:
            parsed_connections.append({'connection': connection})
    return parsed_connections

def get_active_user_sessions():
    result = subprocess.run(['who'], capture_output=True, text=True)
    sessions = result.stdout.splitlines()
    parsed_sessions = [{'session': session} for session in sessions]
    return parsed_sessions

def get_network_routes():
    result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
    routes = result.stdout.splitlines()
    parsed_routes = [{'route': route} for route in routes]
    return parsed_routes

def get_detailed_iptables_rules():
    result = subprocess.run(['iptables', '-L', '-v', '-n'], capture_output=True, text=True)
    rules = result.stdout.splitlines()
    parsed_rules = [{'rule': rule} for rule in rules]
    return parsed_rules

def get_cpu_info():
    result = subprocess.run(['lscpu'], capture_output=True, text=True)
    cpu_info = result.stdout.splitlines()
    parsed_info = [{'info': line} for line in cpu_info]
    return parsed_info

def get_hardware_info():
    result = subprocess.run(['lshw'], capture_output=True, text=True)
    hardware_info = result.stdout.splitlines()
    parsed_info = [{'info': line} for line in hardware_info]
    return parsed_info

def get_grub_config():
    grub_config_path = '/etc/default/grub'
    if os.path.exists(grub_config_path):
        with open(grub_config_path, 'r') as file:
            config = file.readlines()
        return [{'config': line.strip()} for line in config if line.strip()]
    return []

def get_logrotate_config():
    logrotate_path = '/etc/logrotate.conf'
    if os.path.exists(logrotate_path):
        with open(logrotate_path, 'r') as file:
            config = file.readlines()
        return [{'config': line.strip()} for line in config if line.strip()]
    return []

def get_udev_rules():
    result = subprocess.run(['udevadm', 'info', '--export-db'], capture_output=True, text=True)
    udev_rules = result.stdout.splitlines()
    parsed_rules = [{'rule': rule} for rule in udev_rules]
    return parsed_rules

def get_apparmor_status():
    result = subprocess.run(['apparmor_status'], capture_output=True, text=True)
    status = result.stdout.splitlines()
    parsed_status = [{'status': line} for line in status]
    return parsed_status

def get_docker_images():
    result = subprocess.run(['docker', 'images'], capture_output=True, text=True)
    images = result.stdout.splitlines()
    parsed_images = [{'image': image} for image in images]
    return parsed_images

def get_docker_volumes():
    result = subprocess.run(['docker', 'volume', 'ls'], capture_output=True, text=True)
    volumes = result.stdout.splitlines()
    parsed_volumes = [{'volume': volume} for volume in volumes]
    return parsed_volumes

def get_network_shares():
    result = subprocess.run(['smbstatus', '--shares'], capture_output=True, text=True)
    shares = result.stdout.splitlines()
    parsed_shares = [{'share': share} for share in shares]
    return parsed_shares

def get_wifi_networks():
    result = subprocess.run(['nmcli', 'dev', 'wifi'], capture_output=True, text=True)
    networks = result.stdout.splitlines()
    parsed_networks = [{'network': network} for network in networks]
    return parsed_networks

def get_bluetooth_devices():
    result = subprocess.run(['bluetoothctl', 'devices'], capture_output=True, text=True)
    devices = result.stdout.splitlines()
    parsed_devices = [{'device': device} for device in devices]
    return parsed_devices

def get_system_aliases():
    result = subprocess.run(['alias'], capture_output=True, text=True, shell=True)
    aliases = result.stdout.splitlines()
    parsed_aliases = [{'alias': alias} for alias in aliases]
    return parsed_aliases

def get_command_history_for_all_users():
    users = [user['username'] for user in get_user_information()]
    all_history = []
    for user in users:
        history = get_bash_history(f'/home/{user}')
        all_history.extend(history)
    return all_history

def get_installed_services():
    result = subprocess.run(['service', '--status-all'], capture_output=True, text=True)
    services = result.stdout.splitlines()
    parsed_services = [{'service': service} for service in services]
    return parsed_services

def get_kernel_version():
    result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
    kernel_version = result.stdout.strip()
    return {'kernel_version': kernel_version}

def get_disk_partitions():
    result = subprocess.run(['lsblk'], capture_output=True, text=True)
    partitions = result.stdout.splitlines()
    parsed_partitions = [{'partition': partition} for partition in partitions]
    return parsed_partitions

def get_raid_configuration():
    result = subprocess.run(['cat', '/proc/mdstat'], capture_output=True, text=True)
    raid_config = result.stdout.splitlines()
    parsed_config = [{'config': line} for line in raid_config]
    return parsed_config

def get_lvm_configuration():
    result = subprocess.run(['lvm', 'dumpconfig'], capture_output=True, text=True)
    lvm_config = result.stdout.splitlines()
    parsed_config = [{'config': line} for line in lvm_config]
    return parsed_config

def get_sudo_users():
    result = subprocess.run(['getent', 'group', 'sudo'], capture_output=True, text=True)
    sudo_users = result.stdout.strip().split(':')[-1].split(',')
    return [{'user': user} for user in sudo_users]

def get_detailed_process_info():
    result = subprocess.run(['ps', 'auxf'], capture_output=True, text=True)
    processes = result.stdout.splitlines()
    parsed_processes = [{'process': process} for process in processes]
    return parsed_processes

def get_openvpn_config():
    openvpn_path = '/etc/openvpn'
    configs = []
    if os.path.exists(openvpn_path):
        for root, dirs, files in os.walk(openvpn_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    config = f.read()
                configs.append({'file': file_path, 'config': config})
    return configs

def get_running_tasks():
    result = subprocess.run(['atq'], capture_output=True, text=True)
    tasks = result.stdout.splitlines()
    parsed_tasks = [{'task': task} for task in tasks]
    return parsed_tasks

def get_disk_io_stats():
    result = subprocess.run(['iostat'], capture_output=True, text=True)
    stats = result.stdout.splitlines()
    parsed_stats = [{'stat': stat} for stat in stats]
    return parsed_stats

def get_locale_settings():
    result = subprocess.run(['locale'], capture_output=True, text=True)
    locale_settings = result.stdout.splitlines()
    parsed_settings = [{'setting': setting} for setting in locale_settings]
    return parsed_settings

def get_current_logged_in_users():
    result = subprocess.run(['users'], capture_output=True, text=True)
    users = result.stdout.strip().split()
    return [{'user': user} for user in users]

def get_system_services_status():
    result = subprocess.run(['systemctl', 'list-units', '--type=service'], capture_output=True, text=True)
    services = result.stdout.splitlines()
    parsed_services = [{'service': service} for service in services]
    return parsed_services

def get_user_environment_details():
    users = [user['username'] for user in get_user_information()]
    env_details = []
    for user in users:
        env_file = f'/home/{user}/.profile'
        if os.path.exists(env_file):
            with open(env_file, 'r') as file:
                env = file.read()
            env_details.append({'user': user, 'environment': env})
    return env_details

def get_cron_job_status_logs():
    result = subprocess.run(['grep', '-i', 'cron', '/var/log/syslog'], capture_output=True, text=True)
    logs = result.stdout.splitlines()
    parsed_logs = [{'log': log} for log in logs]
    return parsed_logs

def get_software_repositories():
    result = subprocess.run(['cat', '/etc/apt/sources.list'], capture_output=True, text=True)
    repositories = result.stdout.splitlines()
    parsed_repositories = [{'repository': repo} for repo in repositories]
    return parsed_repositories

def get_login_defs():
    login_defs_path = '/etc/login.defs'
    if os.path.exists(login_defs_path):
        with open(login_defs_path, 'r') as file:
            login_defs = file.readlines()
        return [{'config': line.strip()} for line in login_defs if line.strip()]
    return []

def get_ssh_banner():
    ssh_banner_path = '/etc/issue.net'
    if os.path.exists(ssh_banner_path):
        with open(ssh_banner_path, 'r') as file:
            banner = file.read()
        return [{'banner': banner}]
    return []

def get_secure_boot_state():
    result = subprocess.run(['mokutil', '--sb-state'], capture_output=True, text=True)
    secure_boot = result.stdout.strip()
    return {'secure_boot': secure_boot}

def get_kernel_ring_buffer():
    result = subprocess.run(['dmesg'], capture_output=True, text=True)
    kernel_buffer = result.stdout.splitlines()
    parsed_buffer = [{'message': msg} for msg in kernel_buffer]
    return parsed_buffer

def get_network_bond_status():
    result = subprocess.run(['cat', '/proc/net/bonding/bond0'], capture_output=True, text=True)
    bond_status = result.stdout.splitlines()
    parsed_status = [{'status': status} for status in bond_status]
    return parsed_status

def get_samba_config():
    samba_config_path = '/etc/samba/smb.conf'
    if os.path.exists(samba_config_path):
        with open(samba_config_path, 'r') as file:
            config = file.read()
        return [{'config': config}]
    return []

def get_detailed_sysctl_settings():
    result = subprocess.run(['sysctl', '-a'], capture_output=True, text=True)
    sysctl_settings = result.stdout.splitlines()
    parsed_settings = [{'setting': setting} for setting in sysctl_settings]
    return parsed_settings

def get_openssl_version_config():
    result = subprocess.run(['openssl', 'version', '-a'], capture_output=True, text=True)
    openssl_info = result.stdout.splitlines()
    parsed_info = [{'info': info} for info in openssl_info]
    return parsed_info

def get_persistent_iptables_rules():
    iptables_path = '/etc/iptables/rules.v4'
    if os.path.exists(iptables_path):
        with open(iptables_path, 'r') as file:
            rules = file.read()
        return [{'rule': rule} for rule in rules.split('\n') if rule]
    return []

def get_last_logins():
    result = subprocess.run(['lastlog'], capture_output=True, text=True)
    last_logins = result.stdout.splitlines()
    parsed_logins = [{'login': login} for login in last_logins]
    return parsed_logins

def get_active_kernel_threads():
    result = subprocess.run(['ps', '-e', '-T'], capture_output=True, text=True)
    threads = result.stdout.splitlines()
    parsed_threads = [{'thread': thread} for thread in threads]
    return parsed_threads

def get_system_timers():
    result = subprocess.run(['systemctl', 'list-timers'], capture_output=True, text=True)
    timers = result.stdout.splitlines()
    parsed_timers = [{'timer': timer} for timer in timers]
    return parsed_timers

def get_mounted_nfs_filesystems():
    result = subprocess.run(['mount', '-t', 'nfs'], capture_output=True, text=True)
    nfs_mounts = result.stdout.splitlines()
    parsed_mounts = [{'mount': mount} for mount in nfs_mounts]
    return parsed_mounts

def get_system_resource_limits():
    result = subprocess.run(['ulimit', '-a'], capture_output=True, text=True, shell=True)
    resource_limits = result.stdout.splitlines()
    parsed_limits = [{'limit': limit} for limit in resource_limits]
    return parsed_limits

def main():
    parser = argparse.ArgumentParser(description='Collect Linux forensic artifacts.')
    parser.add_argument('-o', '--output-dir', type=str, default='.', help='Output directory for JSON and CSV files')
    parser.add_argument('-u', '--user-home', type=str, default='/home/user', help='User home directory')
    parser.add_argument('-f', '--file-path', type=str, default='/path/to/file', help='File path for metadata')
    
    args = parser.parse_args()
    
    output_dir = args.output_dir
    user_home = args.user_home
    file_path = args.file_path
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Collecting data and saving as JSON and CSV
    syslog_data = parse_syslog('/var/log/syslog')
    save_as_json(syslog_data, os.path.join(output_dir, 'syslog_data'))
    save_as_csv(syslog_data, os.path.join(output_dir, 'syslog_data'), ['date', 'host', 'message'])

    auth_log_data = parse_auth_log('/var/log/auth.log')
    save_as_json(auth_log_data, os.path.join(output_dir, 'auth_log_data'))
    save_as_csv(auth_log_data, os.path.join(output_dir, 'auth_log_data'), ['date', 'host', 'message'])

    file_metadata = get_file_metadata(file_path)
    save_as_json([file_metadata], os.path.join(output_dir, 'file_metadata'))
    save_as_csv([file_metadata], os.path.join(output_dir, 'file_metadata'), file_metadata.keys())

    network_data = get_network_connections()
    save_as_json(network_data, os.path.join(output_dir, 'network_data'))
    save_as_csv(network_data, os.path.join(output_dir, 'network_data'), ['protocol', 'local_address', 'foreign_address', 'state'])

    packages_data = get_installed_packages()
    save_as_json(packages_data, os.path.join(output_dir, 'packages_data'))
    save_as_csv(packages_data, os.path.join(output_dir, 'packages_data'), ['name', 'version', 'description'])

    tasks_data = get_scheduled_tasks()
    save_as_json(tasks_data, os.path.join(output_dir, 'tasks_data'))
    save_as_csv([{'task': task} for task in tasks_data], os.path.join(output_dir, 'tasks_data'), ['task'])

    system_info_data = get_system_info()
    save_as_json([system_info_data], os.path.join(output_dir, 'system_info_data'))
    save_as_csv([system_info_data], os.path.join(output_dir, 'system_info_data'), system_info_data.keys())

    bash_history = get_bash_history(user_home)
    save_as_json(bash_history, os.path.join(output_dir, 'bash_history'))
    save_as_csv(bash_history, os.path.join(output_dir, 'bash_history'), ['command'])

    recent_files = get_recent_files(user_home)
    save_as_json(recent_files, os.path.join(output_dir, 'recent_files'))
    save_as_csv(recent_files, os.path.join(output_dir, 'recent_files'), ['timestamp', 'path'])

    user_sessions = get_user_sessions()
    save_as_json(user_sessions, os.path.join(output_dir, 'user_sessions'))
    save_as_csv(user_sessions, os.path.join(output_dir, 'user_sessions'), ['session'])

    running_processes = get_running_processes()
    save_as_json(running_processes, os.path.join(output_dir, 'running_processes'))
    save_as_csv(running_processes, os.path.join(output_dir, 'running_processes'), ['process'])

    open_files = get_open_files()
    save_as_json(open_files, os.path.join(output_dir, 'open_files'))
    save_as_csv(open_files, os.path.join(output_dir, 'open_files'), ['file'])

    kernel_modules = get_kernel_modules()
    save_as_json(kernel_modules, os.path.join(output_dir, 'kernel_modules'))
    save_as_csv(kernel_modules, os.path.join(output_dir, 'kernel_modules'), ['module', 'size', 'used_by'])

    mounted_filesystems = get_mounted_filesystems()
    save_as_json(mounted_filesystems, os.path.join(output_dir, 'mounted_filesystems'))
    save_as_csv(mounted_filesystems, os.path.join(output_dir, 'mounted_filesystems'), ['filesystem'])

    systemd_services = get_systemd_services()
    save_as_json(systemd_services, os.path.join(output_dir, 'systemd_services'))
    save_as_csv(systemd_services, os.path.join(output_dir, 'systemd_services'), ['service'])

    env_vars = get_environment_variables()
    save_as_json(env_vars, os.path.join(output_dir, 'env_vars'))
    save_as_csv(env_vars, os.path.join(output_dir, 'env_vars'), ['variable', 'value'])

    user_info = get_user_information()
    save_as_json(user_info, os.path.join(output_dir, 'user_info'))
    save_as_csv(user_info, os.path.join(output_dir, 'user_info'), ['username', 'password', 'uid', 'gid', 'gecos', 'home_directory', 'shell'])

    firewall_rules = get_firewall_rules()
    save_as_json(firewall_rules, os.path.join(output_dir, 'firewall_rules'))
    save_as_csv(firewall_rules, os.path.join(output_dir, 'firewall_rules'), ['rule'])

    listening_ports = get_listening_ports()
    save_as_json(listening_ports, os.path.join(output_dir, 'listening_ports'))
    save_as_csv(listening_ports, os.path.join(output_dir, 'listening_ports'), ['port'])

    ssh_config = get_ssh_config()
    save_as_json(ssh_config, os.path.join(output_dir, 'ssh_config'))
    save_as_csv(ssh_config, os.path.join(output_dir, 'ssh_config'), ['config'])

    user_groups = get_user_groups()
    save_as_json(user_groups, os.path.join(output_dir, 'user_groups'))
    save_as_csv(user_groups, os.path.join(output_dir, 'user_groups'), ['group_name', 'password', 'gid', 'members'])

    user_home_dirs = get_user_home_directories()
    save_as_json(user_home_dirs, os.path.join(output_dir, 'user_home_dirs'))
    save_as_csv(user_home_dirs, os.path.join(output_dir, 'user_home_dirs'), ['directory'])

    login_failures = get_login_failures()
    save_as_json(login_failures, os.path.join(output_dir, 'login_failures'))
    save_as_csv(login_failures, os.path.join(output_dir, 'login_failures'), ['failure'])

    system_uptime = get_system_uptime()
    save_as_json([system_uptime], os.path.join(output_dir, 'system_uptime'))
    save_as_csv([system_uptime], os.path.join(output_dir, 'system_uptime'), ['uptime'])

    arp_cache = get_arp_cache()
    save_as_json(arp_cache, os.path.join(output_dir, 'arp_cache'))
    save_as_csv(arp_cache, os.path.join(output_dir, 'arp_cache'), ['entry'])

    dns_cache = get_dns_cache()
    save_as_json(dns_cache, os.path.join(output_dir, 'dns_cache'))
    save_as_csv(dns_cache, os.path.join(output_dir, 'dns_cache'), ['entry'])

    usb_devices = get_usb_devices()
    save_as_json(usb_devices, os.path.join(output_dir, 'usb_devices'))
    save_as_csv(usb_devices, os.path.join(output_dir, 'usb_devices'), ['device'])

    inode_info = get_inode_information(file_path)
    save_as_json(inode_info, os.path.join(output_dir, 'inode_info'))
    save_as_csv(inode_info, os.path.join(output_dir, 'inode_info'), ['inode_info'])

    network_interfaces = get_network_interfaces()
    save_as_json(network_interfaces, os.path.join(output_dir, 'network_interfaces'))
    save_as_csv(network_interfaces, os.path.join(output_dir, 'network_interfaces'), ['interface'])

    boot_logs = get_boot_logs()
    save_as_json(boot_logs, os.path.join(output_dir, 'boot_logs'))
    save_as_csv(boot_logs, os.path.join(output_dir, 'boot_logs'), ['log'])

    memory_usage = get_memory_usage()
    save_as_json(memory_usage, os.path.join(output_dir, 'memory_usage'))
    save_as_csv(memory_usage, os.path.join(output_dir, 'memory_usage'), ['memory_usage'])

    disk_usage = get_disk_usage()
    save_as_json(disk_usage, os.path.join(output_dir, 'disk_usage'))
    save_as_csv(disk_usage, os.path.join(output_dir, 'disk_usage'), ['disk_usage'])

    sudo_logs = get_sudo_logs()
    save_as_json(sudo_logs, os.path.join(output_dir, 'sudo_logs'))
    save_as_csv(sudo_logs, os.path.join(output_dir, 'sudo_logs'), ['log'])

    docker_containers = get_docker_containers()
    save_as_json(docker_containers, os.path.join(output_dir, 'docker_containers'))
    save_as_csv(docker_containers, os.path.join(output_dir, 'docker_containers'), ['container'])

    all_user_crontabs = get_all_user_crontabs()
    save_as_json(all_user_crontabs, os.path.join(output_dir, 'all_user_crontabs'))
    # For CSV, we'll need a flat structure, so we'll convert the nested crontabs to strings
    flat_crontabs = [{'user': c['user'], 'crontab': '\n'.join(c['crontab'])} for c in all_user_crontabs]
    save_as_csv(flat_crontabs, os.path.join(output_dir, 'all_user_crontabs'), ['user', 'crontab'])

    audit_logs = get_audit_logs()
    save_as_json(audit_logs, os.path.join(output_dir, 'audit_logs'))
    save_as_csv(audit_logs, os.path.join(output_dir, 'audit_logs'), ['log'])

    systemd_journal_logs = get_systemd_journal_logs()
    save_as_json(systemd_journal_logs, os.path.join(output_dir, 'systemd_journal_logs'))
    save_as_csv(systemd_journal_logs, os.path.join(output_dir, 'systemd_journal_logs'), ['log'])

    selinux_status = get_selinux_status()
    save_as_json(selinux_status, os.path.join(output_dir, 'selinux_status'))
    save_as_csv(selinux_status, os.path.join(output_dir, 'selinux_status'), ['status'])

    pam_configuration = get_pam_configuration()
    save_as_json(pam_configuration, os.path.join(output_dir, 'pam_configuration'))
    # For CSV, we'll need a flat structure, so we'll convert the nested config to strings
    flat_pam_config = [{'file': p['file'], 'config': '\n'.join(p['config'])} for p in pam_configuration]
    save_as_csv(flat_pam_config, os.path.join(output_dir, 'pam_configuration'), ['file', 'config'])

    kernel_boot_parameters = get_kernel_boot_parameters()
    save_as_json([kernel_boot_parameters], os.path.join(output_dir, 'kernel_boot_parameters'))
    save_as_csv([kernel_boot_parameters], os.path.join(output_dir, 'kernel_boot_parameters'), ['boot_parameters'])

    ssh_known_hosts = get_ssh_known_hosts(user_home)
    save_as_json(ssh_known_hosts, os.path.join(output_dir, 'ssh_known_hosts'))
    save_as_csv(ssh_known_hosts, os.path.join(output_dir, 'ssh_known_hosts'), ['host'])

    python_packages = get_installed_python_packages()
    save_as_json(python_packages, os.path.join(output_dir, 'python_packages'))
    save_as_csv(python_packages, os.path.join(output_dir, 'python_packages'), ['package'])

    ruby_gems = get_installed_ruby_gems()
    save_as_json(ruby_gems, os.path.join(output_dir, 'ruby_gems'))
    save_as_csv(ruby_gems, os.path.join(output_dir, 'ruby_gems'), ['gem'])

    node_packages = get_installed_node_packages()
    save_as_json(node_packages, os.path.join(output_dir, 'node_packages'))
    save_as_csv(node_packages, os.path.join(output_dir, 'node_packages'), ['package'])

    hostname = get_system_hostname()
    save_as_json([hostname], os.path.join(output_dir, 'hostname'))
    save_as_csv([hostname], os.path.join(output_dir, 'hostname'), ['hostname'])

    timezone_info = get_system_timezone()
    save_as_json(timezone_info, os.path.join(output_dir, 'timezone_info'))
    save_as_csv(timezone_info, os.path.join(output_dir, 'timezone_info'), ['info'])

    active_network_connections = get_active_network_connections()
    save_as_json(active_network_connections, os.path.join(output_dir, 'active_network_connections'))
    save_as_csv(active_network_connections, os.path.join(output_dir, 'active_network_connections'), ['connection'])

    active_user_sessions = get_active_user_sessions()
    save_as_json(active_user_sessions, os.path.join(output_dir, 'active_user_sessions'))
    save_as_csv(active_user_sessions, os.path.join(output_dir, 'active_user_sessions'), ['session'])

    network_routes = get_network_routes()
    save_as_json(network_routes, os.path.join(output_dir, 'network_routes'))
    save_as_csv(network_routes, os.path.join(output_dir, 'network_routes'), ['route'])

    detailed_iptables_rules = get_detailed_iptables_rules()
    save_as_json(detailed_iptables_rules, os.path.join(output_dir, 'detailed_iptables_rules'))
    save_as_csv(detailed_iptables_rules, os.path.join(output_dir, 'detailed_iptables_rules'), ['rule'])

    cpu_info = get_cpu_info()
    save_as_json(cpu_info, os.path.join(output_dir, 'cpu_info'))
    save_as_csv(cpu_info, os.path.join(output_dir, 'cpu_info'), ['info'])

    hardware_info = get_hardware_info()
    save_as_json(hardware_info, os.path.join(output_dir, 'hardware_info'))
    save_as_csv(hardware_info, os.path.join(output_dir, 'hardware_info'), ['info'])

    grub_config = get_grub_config()
    save_as_json(grub_config, os.path.join(output_dir, 'grub_config'))
    save_as_csv(grub_config, os.path.join(output_dir, 'grub_config'), ['config'])

    logrotate_config = get_logrotate_config()
    save_as_json(logrotate_config, os.path.join(output_dir, 'logrotate_config'))
    save_as_csv(logrotate_config, os.path.join(output_dir, 'logrotate_config'), ['config'])

    udev_rules = get_udev_rules()
    save_as_json(udev_rules, os.path.join(output_dir, 'udev_rules'))
    save_as_csv(udev_rules, os.path.join(output_dir, 'udev_rules'), ['rule'])

    apparmor_status = get_apparmor_status()
    save_as_json(apparmor_status, os.path.join(output_dir, 'apparmor_status'))
    save_as_csv(apparmor_status, os.path.join(output_dir, 'apparmor_status'), ['status'])

    docker_images = get_docker_images()
    save_as_json(docker_images, os.path.join(output_dir, 'docker_images'))
    save_as_csv(docker_images, os.path.join(output_dir, 'docker_images'), ['image'])

    docker_volumes = get_docker_volumes()
    save_as_json(docker_volumes, os.path.join(output_dir, 'docker_volumes'))
    save_as_csv(docker_volumes, os.path.join(output_dir, 'docker_volumes'), ['volume'])

    network_shares = get_network_shares()
    save_as_json(network_shares, os.path.join(output_dir, 'network_shares'))
    save_as_csv(network_shares, os.path.join(output_dir, 'network_shares'), ['share'])

    wifi_networks = get_wifi_networks()
    save_as_json(wifi_networks, os.path.join(output_dir, 'wifi_networks'))
    save_as_csv(wifi_networks, os.path.join(output_dir, 'wifi_networks'), ['network'])

    bluetooth_devices = get_bluetooth_devices()
    save_as_json(bluetooth_devices, os.path.join(output_dir, 'bluetooth_devices'))
    save_as_csv(bluetooth_devices, os.path.join(output_dir, 'bluetooth_devices'), ['device'])

    system_aliases = get_system_aliases()
    save_as_json(system_aliases, os.path.join(output_dir, 'system_aliases'))
    save_as_csv(system_aliases, os.path.join(output_dir, 'system_aliases'), ['alias'])

    command_history = get_command_history_for_all_users()
    save_as_json(command_history, os.path.join(output_dir, 'command_history'))
    save_as_csv(command_history, os.path.join(output_dir, 'command_history'), ['command'])

    installed_services = get_installed_services()
    save_as_json(installed_services, os.path.join(output_dir, 'installed_services'))
    save_as_csv(installed_services, os.path.join(output_dir, 'installed_services'), ['service'])

    kernel_version = get_kernel_version()
    save_as_json([kernel_version], os.path.join(output_dir, 'kernel_version'))
    save_as_csv([kernel_version], os.path.join(output_dir, 'kernel_version'), ['kernel_version'])

    disk_partitions = get_disk_partitions()
    save_as_json(disk_partitions, os.path.join(output_dir, 'disk_partitions'))
    save_as_csv(disk_partitions, os.path.join(output_dir, 'disk_partitions'), ['partition'])

    raid_configuration = get_raid_configuration()
    save_as_json(raid_configuration, os.path.join(output_dir, 'raid_configuration'))
    save_as_csv(raid_configuration, os.path.join(output_dir, 'raid_configuration'), ['config'])

    lvm_configuration = get_lvm_configuration()
    save_as_json(lvm_configuration, os.path.join(output_dir, 'lvm_configuration'))
    save_as_csv(lvm_configuration, os.path.join(output_dir, 'lvm_configuration'), ['config'])

    sudo_users = get_sudo_users()
    save_as_json(sudo_users, os.path.join(output_dir, 'sudo_users'))
    save_as_csv(sudo_users, os.path.join(output_dir, 'sudo_users'), ['user'])

    detailed_process_info = get_detailed_process_info()
    save_as_json(detailed_process_info, os.path.join(output_dir, 'detailed_process_info'))
    save_as_csv(detailed_process_info, os.path.join(output_dir, 'detailed_process_info'), ['process'])

    openvpn_config = get_openvpn_config()
    save_as_json(openvpn_config, os.path.join(output_dir, 'openvpn_config'))
    # For CSV, we'll need a flat structure, so we'll convert the nested config to strings
    flat_openvpn_config = [{'file': c['file'], 'config': c['config']} for c in openvpn_config]
    save_as_csv(flat_openvpn_config, os.path.join(output_dir, 'openvpn_config'), ['file', 'config'])

    running_tasks = get_running_tasks()
    save_as_json(running_tasks, os.path.join(output_dir, 'running_tasks'))
    save_as_csv(running_tasks, os.path.join(output_dir, 'running_tasks'), ['task'])

    disk_io_stats = get_disk_io_stats()
    save_as_json(disk_io_stats, os.path.join(output_dir, 'disk_io_stats'))
    save_as_csv(disk_io_stats, os.path.join(output_dir, 'disk_io_stats'), ['stat'])

    locale_settings = get_locale_settings()
    save_as_json(locale_settings, os.path.join(output_dir, 'locale_settings'))
    save_as_csv(locale_settings, os.path.join(output_dir, 'locale_settings'), ['setting'])

    current_logged_in_users = get_current_logged_in_users()
    save_as_json(current_logged_in_users, os.path.join(output_dir, 'current_logged_in_users'))
    save_as_csv(current_logged_in_users, os.path.join(output_dir, 'current_logged_in_users'), ['user'])

    system_services_status = get_system_services_status()
    save_as_json(system_services_status, os.path.join(output_dir, 'system_services_status'))
    save_as_csv(system_services_status, os.path.join(output_dir, 'system_services_status'), ['service'])

    user_environment_details = get_user_environment_details()
    save_as_json(user_environment_details, os.path.join(output_dir, 'user_environment_details'))
    # For CSV, we'll need a flat structure, so we'll convert the nested env to strings
    flat_user_env_details = [{'user': e['user'], 'environment': e['environment']} for e in user_environment_details]
    save_as_csv(flat_user_env_details, os.path.join(output_dir, 'user_environment_details'), ['user', 'environment'])

    cron_job_status_logs = get_cron_job_status_logs()
    save_as_json(cron_job_status_logs, os.path.join(output_dir, 'cron_job_status_logs'))
    save_as_csv(cron_job_status_logs, os.path.join(output_dir, 'cron_job_status_logs'), ['log'])

    software_repositories = get_software_repositories()
    save_as_json(software_repositories, os.path.join(output_dir, 'software_repositories'))
    save_as_csv(software_repositories, os.path.join(output_dir, 'software_repositories'), ['repository'])

    login_defs = get_login_defs()
    save_as_json(login_defs, os.path.join(output_dir, 'login_defs'))
    save_as_csv(login_defs, os.path.join(output_dir, 'login_defs'), ['config'])

    ssh_banner = get_ssh_banner()
    save_as_json(ssh_banner, os.path.join(output_dir, 'ssh_banner'))
    save_as_csv(ssh_banner, os.path.join(output_dir, 'ssh_banner'), ['banner'])

    secure_boot_state = get_secure_boot_state()
    save_as_json([secure_boot_state], os.path.join(output_dir, 'secure_boot_state'))
    save_as_csv([secure_boot_state], os.path.join(output_dir, 'secure_boot_state'), ['secure_boot'])

    kernel_ring_buffer = get_kernel_ring_buffer()
    save_as_json(kernel_ring_buffer, os.path.join(output_dir, 'kernel_ring_buffer'))
    save_as_csv(kernel_ring_buffer, os.path.join(output_dir, 'kernel_ring_buffer'), ['message'])

    network_bond_status = get_network_bond_status()
    save_as_json(network_bond_status, os.path.join(output_dir, 'network_bond_status'))
    save_as_csv(network_bond_status, os.path.join(output_dir, 'network_bond_status'), ['status'])

    samba_config = get_samba_config()
    save_as_json(samba_config, os.path.join(output_dir, 'samba_config'))
    save_as_csv(samba_config, os.path.join(output_dir, 'samba_config'), ['config'])

    detailed_sysctl_settings = get_detailed_sysctl_settings()
    save_as_json(detailed_sysctl_settings, os.path.join(output_dir, 'detailed_sysctl_settings'))
    save_as_csv(detailed_sysctl_settings, os.path.join(output_dir, 'detailed_sysctl_settings'), ['setting'])

    openssl_version_config = get_openssl_version_config()
    save_as_json(openssl_version_config, os.path.join(output_dir, 'openssl_version_config'))
    save_as_csv(openssl_version_config, os.path.join(output_dir, 'openssl_version_config'), ['info'])

    persistent_iptables_rules = get_persistent_iptables_rules()
    save_as_json(persistent_iptables_rules, os.path.join(output_dir, 'persistent_iptables_rules'))
    save_as_csv(persistent_iptables_rules, os.path.join(output_dir, 'persistent_iptables_rules'), ['rule'])

    last_logins = get_last_logins()
    save_as_json(last_logins, os.path.join(output_dir, 'last_logins'))
    save_as_csv(last_logins, os.path.join(output_dir, 'last_logins'), ['login'])

    active_kernel_threads = get_active_kernel_threads()
    save_as_json(active_kernel_threads, os.path.join(output_dir, 'active_kernel_threads'))
    save_as_csv(active_kernel_threads, os.path.join(output_dir, 'active_kernel_threads'), ['thread'])

    system_timers = get_system_timers()
    save_as_json(system_timers, os.path.join(output_dir, 'system_timers'))
    save_as_csv(system_timers, os.path.join(output_dir, 'system_timers'), ['timer'])

    mounted_nfs_filesystems = get_mounted_nfs_filesystems()
    save_as_json(mounted_nfs_filesystems, os.path.join(output_dir, 'mounted_nfs_filesystems'))
    save_as_csv(mounted_nfs_filesystems, os.path.join(output_dir, 'mounted_nfs_filesystems'), ['mount'])

    system_resource_limits = get_system_resource_limits()
    save_as_json(system_resource_limits, os.path.join(output_dir, 'system_resource_limits'))
    save_as_csv(system_resource_limits, os.path.join(output_dir, 'system_resource_limits'), ['limit'])

if __name__ == '__main__':
    main()
