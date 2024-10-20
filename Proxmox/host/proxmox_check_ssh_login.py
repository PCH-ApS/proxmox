#!/usr/bin/env python3

import json
import sys
import paramiko

print("-------------------------------------------")
print("--         Validate Proxmox login        --")
print("-------------------------------------------")

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        sys.exit(1)

def test_ssh_login(hostname, username):
    """Test SSH login to the specified host using public key authentication."""
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the SSH public key
        ssh.connect(hostname=hostname, username=username)

        # If the connection is successful, print a success message
        print(f"\033[92m[SUCCESS]         : Connected as {username} to {hostname}.")

        # Close the connection
        ssh.close()
        return True
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to connect to {hostname} as {username}: {e}")
        return False

def process_hosts_and_users(config):
    """Process hosts and users from the configuration."""
    pve_host = config.get("PVE_HOST")
    pve_user = config.get("PVE_USER")

    if not pve_host or not pve_user:
        print("\033[91m[ERROR]           : Missing 'PVE_HOST' or 'PVE_USER' in the configuration.")
        return

    hostname = pve_host.get("host_ip")
    username = pve_user.get("username")

    if not hostname:
        print("\033[91m[ERROR]           : Missing 'host_ip' in 'PVE_HOST'.")
    if not username:
        print("\033[91m[ERROR]           : Missing 'username' in 'PVE_USER'.")

    if hostname and username:
        print(f"\033[92m[INFO]            : Attempting to connect to Host - IP: {hostname}, Username: {username}")
        # Test the SSH connection
        test_ssh_login(hostname, username)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: script.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    process_hosts_and_users(config)
    end_output_to_shell()
