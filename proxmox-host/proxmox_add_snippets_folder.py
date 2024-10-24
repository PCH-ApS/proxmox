#!/usr/bin/env python3

import json
import sys
import paramiko

# Utility function for output end
def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

# Function to load configuration from JSON file
def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        return None

# Function to extract specific values from config
def get_json_values(config):
    """Extract necessary values from the config."""
    return {
        "pve_user": config.get("PVE_USER", {}).get("username"),
        "pve_host": config.get("PVE_HOST", {}).get("host_ip")
    }

# Function to establish an SSH connection
def establish_ssh_connection(hostname, username):
    """Establish an SSH connection and return the client."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=hostname, username=username)
        return ssh
    except Exception as e:
        print(f"\033[91m[ERROR]           : SSH connection failed: {e}")
        return None

# Function to execute commands over SSH
def execute_ssh_commands(ssh_client, commands):
    """Execute a list of commands over SSH."""
    for command in commands:
        try:
            stdin, stdout, stderr = ssh_client.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"\033[91m[ERROR]           : Command '{command}' failed with error: {error_output}")
                return False
            else:
                print(f"\033[92m[SUCCESS]         : Command '{command}' executed successfully.")
        except Exception as e:
            print(f"\033[91m[ERROR]           : Failed to execute command '{command}': {e}")
            return False
    return True

# Function to add snippets folder via SSH
def add_snippets_folder(values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")

    if not pve_hostip or not pve_username:
        print("\033[91m[ERROR]           : Host IP or Username missing in configuration.")
        return

    # SSH connection
    ssh_client = establish_ssh_connection(pve_hostip, pve_username)
    if not ssh_client:
        return

    # Define the commands
    commands = [
        "if [ ! -d '/var/lib/vz/snippets' ]; then mkdir /var/lib/vz/snippets; fi"
    ]

    # Execute the commands
    success = execute_ssh_commands(ssh_client, commands)
    ssh_client.close()

    if success:
        print(f"\033[92m[SUCCESS]         : Snippets folder created or already exists on {pve_hostip}.")
    else:
        print("\033[91m[ERROR]           : Failed to create snippets folder.")

# Main function
def main(config_file):
    config = load_config(config_file)
    if not config:
        sys.exit(1)

    values = get_json_values(config)
    if not values:
        sys.exit(1)

    add_snippets_folder(values)
    end_output_to_shell()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: check_spaces.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    main(config_file)
