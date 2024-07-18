# NIX_Triage
Just a python script to parse as much as NIX based artefacts for Incident Response. It is developed to cover both LINUX and MAC OSX artefacts

## Prerequisites
- Ensure Python is installed on your system.
- Install any required Python packages if needed.
    
## How to Use
Instructions to Use the Script:

- Save the script as nix_triage.py.
- Open a terminal or command prompt.
- Navigate to the directory where the script is saved.
- Run the script using the following command:

   `python nix_triage.py -o /path/to/output -u /home/username -f /path/to/specific/file`

## Help Output
To see the help message and usage instructions, you can run:

`python nix_triage.py --help`

Command Line Flags and Options

    -h, --help: Show the help message and exit.
    -o, --output-dir: Specify the output directory for JSON and CSV files. Default is the current directory.
    -u, --user-home: Specify the user home directory to collect bash history and recent files. Default is /home/user.
    -f, --file-path: Specify a file path to collect file metadata. Default is /path/to/file.


## Notes
- Ensure you have the necessary permissions to run the script and access system files.
- Adjust the file paths, user home directories, and output directories as needed.
- This script collects extensive forensic artifacts, which may take some time to complete.
- The script saves both JSON and CSV formats for each type of collected data in the specified output directory.
- The script automatically detects whether it is running on Linux or macOS and adjusts its commands accordingly.

## Artifacts Collected and Parsed
The script covers a comprehensive range of forensic artifacts for both Linux and macOS systems. Here is a list of all the artifacts that are collected:

### System Logs

    Syslog (/var/log/syslog)
    Authentication logs (/var/log/auth.log)

### File Metadata

    Metadata of a specified file (path provided by the user)

### Network Information

    Network connections (using netstat)
    ARP cache (using arp)
    DNS cache
    Network interfaces (using ifconfig)
    Active network connections (using ss)
    Network routes (using ip route)
    Listening ports (using netstat)

### Installed Software

    Installed packages (using dpkg for Linux, brew for macOS)
    Installed Python packages (using pip)
    Installed Ruby gems (using gem)
    Installed Node.js packages (using npm)

### System Information

    General system information (using platform)
    Kernel version (using uname -r)
    CPU information (using lscpu or sysctl)
    Hardware information (using lshw or system_profiler)

### User Information

    User information (using getent passwd)
    User groups (using getent group)
    User home directories (listing /home/* or /Users/*)
    Active user sessions (using who)
    Command history for all users (using .bash_history)

### System Configuration

    Environment variables (using os.environ)
    SSH configuration (/etc/ssh/sshd_config)
    SSH known hosts (.ssh/known_hosts)
    Kernel boot parameters (/proc/cmdline)
    PAM configuration (/etc/pam.d/)
    System aliases (using alias)
    Systemd services (using systemctl or launchctl)
    Running processes (using ps aux)
    Detailed process information (using ps auxf)
    Scheduled tasks (using crontab)
    All user crontabs (using crontab -u)
    Running tasks (using atq)
    Mounted filesystems (using mount)
    Mounted NFS filesystems (using mount -t nfs)
    System resource limits (using ulimit)
    Firewall rules (using iptables or pfctl)
    Detailed iptables rules (using iptables -L -v -n or pfctl -sr)
    Persistent iptables rules (/etc/iptables/rules.v4)

### Logs and Audit

    Login failures (using grep in /var/log/auth.log or /var/log/system.log)
    Boot logs (using journalctl -b or log show --predicate)
    Sudo logs (/var/log/sudo.log or /var/log/system.log)
    Systemd journal logs (using journalctl)
    Audit logs (using ausearch or log show --predicate)
    Cron job status logs (using grep in /var/log/syslog or /var/log/system.log)

### File and Directory Information

    Inode information (using ls -i)
    Recent files (using find or mdfind)
    Open files (using lsof)

### Kernel and Modules

    Kernel modules (using lsmod or kextstat)
    Kernel ring buffer (using dmesg)
    Active kernel threads (using ps -e -T)

### Containers and Virtualization

    Docker containers (using docker ps)
    Docker images (using docker images)
    Docker volumes (using docker volume ls)

### Security and Permissions

    SELinux status (using sestatus)
    AppArmor status (using apparmor_status)
    Sudo users (using getent group sudo)
    Secure boot state (using mokutil --sb-state)

### Storage and Filesystems

    Disk usage (using df -h)
    Disk partitions (using lsblk)
    Disk I/O statistics (using iostat)
    RAID configuration (/proc/mdstat)
    LVM configuration (using lvm dumpconfig)

### Networking and Sharing

    Network shares (using smbstatus or smbutil)
    WiFi networks (using nmcli or airport)
    Bluetooth devices (using bluetoothctl or system_profiler)
    Network bond status (/proc/net/bonding/bond0)

### Configuration Files

    GRUB configuration (/etc/default/grub)
    Logrotate configuration (/etc/logrotate.conf)
    Udev rules (using udevadm)
    Samba configuration (/etc/samba/smb.conf)
    Log definitions (/etc/login.defs)
    SSH banner (/etc/issue.net)

### Miscellaneous

    System uptime (using uptime)
    Locale settings (using locale)
    System timers (using systemctl list-timers)
    System services status (using systemctl or launchctl)
    User environment details (from .profile)
    Software repositories (/etc/apt/sources.list or brew tap)
    OpenVPN configuration (/etc/openvpn if exists)
    SSL version configuration (using openssl version -a)
