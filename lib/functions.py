#!/usr/bin/env python3
# lib/functions.py

import sys
import paramiko
import time
import re
import getpass
import os

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def ssh_connect(host, username, password=None):
    """Establish SSH connection to the remote host securely using key-based auth."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(hostname=host, username=username, password=password)
        else:
            ssh.connect(hostname=host, username=username)
        print(f"\033[92m[SUCCESS]         : Successfully connected to {host} as {username}.")
        return ssh
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to connect to {host} as {username}: {e}")
        end_output_to_shell()
        sys.exit(1)

def execute_ssh_command(ssh, command, error_message=None):
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    error_output = stderr.read().decode().strip()
    if exit_status != 0:
        if error_message:
            print(f"\033[91m[ERROR]           : {error_message}: {error_output}\033[0m")
        sys.exit(1)
    return stdout.read().decode().strip()

def execute_ssh_sudo_command(ssh, sudo_env, command, error_message=None):
    sudo_password = os.getenv(sudo_env)

    if not sudo_password:
        raise EnvironmentError("The environment variable 'CI_PASSWORD' is not set. Please set it before running the script.")

    # Construct the sudo command with the password
    # sudo_command = f"echo {sudo_password} | sudo -S -p '' bash -c '{command}'"
    sudo_command = f'echo {sudo_password} | sudo -S -p "" bash -c "{command}"'

    try:
        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command.

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            if error_message:
                print(f"\033[91m[ERROR]           : {error_message}: {error_output}\033[0m")
            sys.exit(1)

        return output

    except Exception as e:
        print(f"An unexpected error occurred while executing the command: {e}")
        sys.exit(1)

def change_remote_password(ssh, sudo_env, new_password, ci_username):
    sudo_password = os.getenv(sudo_env)
    new_password = os.getenv(new_password)

    if not sudo_password:
        raise EnvironmentError("The environment variable 'CI_PASSWORD' is not set. Please set it before running the script.")

    if not new_password:
        raise EnvironmentError("The environment variable 'NEW_PASSWORD' is not set. Please set it before running the script.")

    # Construct the sudo command with the password
    #command = f"echo '{ci_username}:{new_password}' | sudo chpasswd"
    #sudo_command = f'echo {sudo_password} | sudo -S -p "" bash -c "{command}"'
    #sudo_command = echo password | sudo -S -p "" bash -c "echo 'pch:password1' | chpasswd"
    sudo_command = f"echo {sudo_password} | sudo -S -p \"\" bash -c \"echo '{ci_username}:{new_password}' | chpasswd\""


    try:
        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command.

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            print(f"\033[91m[ERROR]           : Failed to change password on {ci_username}: {error_output}\033[0m")
            sys.exit(1)

        return output

    except Exception as e:
        print(f"An unexpected error occurred while executing the command: {e}")
        sys.exit(1)

def wait_for_reboot(host, username, password=None, timeout=300, interval=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                ssh.connect(hostname=host, username=username, password=password)
            else:
                ssh.connect(hostname=host, username=username)
            print(f"\033[92m[SUCCESS]         : Successfully reconnected to {host} after reboot.")
            return ssh
        except Exception:
            print(f"\033[93m[INFO]            : Waiting for VM '{host}' to reboot...")
            time.sleep(interval)
    print(f"\033[91m[ERROR]           : Timeout while waiting for {host} to reboot.")
    sys.exit(1)

def is_valid_hostname(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        return False

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        return False

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            return False
        if not hostname_regex.match(label):  # Each label must match the regex
            return False

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            return False

    return True

def check_valid_ip_address(values, which_ip):
    if which_ip == "host":
      value_string = values.get("ci_ipaddress")
    if which_ip == "gw":
      value_string = values.get("ci_gwadvalue")
    if which_ip == "dns":
      value_string = values.get("ci_dns_server")
    parts = value_string.split('.')
    vlan = values.get("vlan")

    if len(parts) != 4:
        print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. IP address should have exactly four parts.")
        end_output_to_shell()
        sys.exit(1)

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be between 0 and 255.")
                end_output_to_shell()
                sys.exit(1)
        except ValueError:
            print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be an integer.")
            end_output_to_shell()
            sys.exit(1)

    print(f"\033[92m[INFO]            : IP address '{value_string}' is a valid ip-address.")

    if which_ip == "dns":
      if not int(vlan) == int(parts[2]):
          print(f"\033[92m[INFO]            : DNS IP address 3rd octect '{parts[2]}' does not match VLAN ID '{vlan}'. Continuing...")

    if not which_ip == "dns":
      if not int(vlan) == int(parts[2]):
        print(f"\033[91m[ERROR]           : IP address 3rd octect '{parts[2]}' does not match VLAN ID '{vlan}'.")
        end_output_to_shell()
        sys.exit(1)

def check_netmask(values):
    value_string = values.get("ci_netmask")
    try:
        netmask = int(value_string)
        if not netmask in range(23, 30):
            print(f"\033[91m[ERROR]           : Invalid netmask '{value_string}'. Netmask is not a number between /24 and /29.")
            return
    except ValueError:
        print(f"\033[91m[ERROR]           : Invalid netmask '{value_string}'. Netmask is not a number value.")
        return

    print(f"\033[92m[INFO]            : Netmask '/{netmask}' is a valid netmask.")

def check_vlan(values):
    value_string = values.get("vlan")
    try:
        vlan= int(value_string)
        if not vlan in range(2, 4095):
            print(f"\033[91m[ERROR]           : Invalid VLAN '{vlan}'. Vlan should be a number between 2 and 4094.")
            end_output_to_shell()
            sys.exit(1)

    except ValueError:
        print(f"\033[91m[ERROR]           : Invalid VLAN '{value_string}'. Vlan id must be a number.")
        end_output_to_shell()
        sys.exit(1)

    print(f"\033[92m[INFO]            : VLAN id '{value_string}' is a valid VLAN.")

def change_remote_password(remote_host, remote_user, new_password, ssh=None):

    try:
        # Create an SSH client if none is provided
        if ssh is None:
            ssh = ssh_connect(remote_host, remote_user)

        # Determine if the password is for the current user or a different user
        current_user = get_current_user(ssh)
        if current_user is None:
            print(f"\033[91m[ERROR]           : Unable to determine the current user.")
            return False

        if remote_user == current_user:
            change_password_cmd = f'echo "{remote_user}:{new_password}" | chpasswd'

        else:
            # Prompt for sudo password for changing another user's password
            print(f"\033[93m[INFO]            : Changing password for user '{remote_user}' on {remote_host} requires sudo privileges.")
            sudo_password = getpass.getpass(prompt="Enter sudo password: ")

            # Use expect script to change the password for another user using sudo
            change_password_cmd = f"echo '{sudo_password}' | sudo -S sh -c \"echo '{remote_user}:{new_password}' | chpasswd\""

        # Execute the command
        print(f"\033[92m[INFO]            : Changing password for user '{remote_user}' on {remote_host}...")
        stdin, stdout, stderr = ssh.exec_command(change_password_cmd)

        # Wait for the command to finish and check for errors
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print(f"\033[92m[SUCCESS]         : Password for user '{remote_user}' on {remote_host} has been updated successfully.")
            return True
        else:
            error_message = stderr.read().decode().strip()
            print(f"\033[91m[ERROR]           : Failed to update password. Error: {error_message}")
            return False

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error updating password on {remote_host}: {e}")
        return False

    finally:
        if ssh is not None:
            ssh.close()
            print(f"\033[92m[INFO]            : SSH connection to {remote_host} closed.")

def get_new_password(remote_user, remote_host):
    """Prompt user to enter a new password."""
    print(f"\033[93m[INFO]            : Enter the new password for the user '{remote_user}' on '{remote_host}':")
    new_password = getpass.getpass(prompt="New Password: ")
    return new_password

def get_current_user(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("whoami")
        current_user = stdout.read().decode().strip()
        return current_user
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to get current user on remote host: {e}")
        return None