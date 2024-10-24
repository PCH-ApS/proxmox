#!/usr/bin/env python3

import json
import sys
import paramiko
import getpass

print("-------------------------------------------")
print("--       Change PW on proxmox root       --")
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

def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip")
    }

def change_remote_password(remote_user, remote_host, new_password):
    """Change the password of a remote user on the Proxmox host."""
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote host
        print(f"\033[92m[INFO]            : Connecting to {remote_host} as {remote_user}...")
        ssh.connect(hostname=remote_host, username=remote_user)

        # Command to change the password on the remote host
        change_password_cmd = f'echo "{remote_user}:{new_password}" | chpasswd'

        # Execute the command
        print(f"\033[92m[INFO]            : Changing password on {remote_host}...")
        stdin, stdout, stderr = ssh.exec_command(change_password_cmd)

        # Wait for the command to finish and check for errors
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print(f"\033[92m[SUCCESS]         : Password for user {remote_user} on {remote_host} has been updated successfully.")
        else:
            error_message = stderr.read().decode().strip()
            print(f"\033[91m[ERROR]           : Failed to update password. Error: {error_message}")
            sys.exit(1)

        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to {remote_host}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check if the correct number of arguments are provided
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: script.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    # Load the JSON configuration file
    config_file = sys.argv[1]
    config = load_config(config_file)
    values = get_json_values(config)

    # Retrieve user and host details from JSON
    remote_user = values.get("pve_user")
    remote_host = values.get("pve_host")

    # Prompt for the new password
    print(f"\033[93m[INFO]            : Enter the new password for the user {remote_user} on {remote_host}:")
    new_password = getpass.getpass(prompt="New Password: ")

    # Change the password on the remote Proxmox host
    change_remote_password(remote_user, remote_host, new_password)

    end_output_to_shell()
