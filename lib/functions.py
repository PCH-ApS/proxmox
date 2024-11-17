#!/usr/bin/env python3
# lib/functions.py

import sys
import paramiko
import time
import re
import getpass
import os


def ssh_connect(host, username, password=None, key_filename=None):
    # Establish SSH connection to the remote
    # host securely using key-based auth.
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(
                hostname=host,
                username=username,
                password=password
            )
        elif key_filename:
            ssh.connect(
                hostname=host,
                username=username,
                key_filename=key_filename
            )
        else:
            ssh.connect(
                hostname=host,
                username=username
            )
        output_message(
            f"Successfully connected to {host} as {username}.",
            "s"
        )
        return ssh
    except paramiko.AuthenticationException:
        output_message(
            f"Authentication failed when connecting to {host}.",
            "Please check your credentials.",
            "e"
        )
    except paramiko.SSHException as e:
        output_message(
            f"Unable to establish SSH connection to {host}: {e}",
            "e"
        )
    except Exception as e:
        output_message(
            f"Unexpected error while connecting to {host}: {e}",
            "e"
        )
    return None

def execute_ssh_command(ssh, command, error_message=None):
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    error_output = stderr.read().decode().strip()
    if exit_status != 0:
        if error_message:
            output_message(f"{error_message}: {error_output}", "e")
    return stdout.read().decode().strip()


def execute_ssh_sudo_command(ssh, sudo_env, command, error_message=None):
    sudo_password = os.getenv(sudo_env)

    if not sudo_password:
        raise EnvironmentError(
            "The environment variable 'CI_PASSWORD' is not set.",
            " Please set it before running the script."
        )

    # Construct the sudo command with the password
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
                output_message(f"{error_message}: {error_output}", "e")
            sys.exit(1)

        return output

    except Exception as e:
        print(f"An unexpected error occurred while executing the command: {e}")


def wait_for_reboot(host, username, password=None, timeout=300, interval=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                ssh.connect(host, username, password)
            else:
                ssh.connect(host, username)
            output_message(
                f"Successfully reconnected to {host} after reboot.",
                "s"
                )
            return ssh
        except Exception:
            print(f"\033[93m[INFO]            : Waiting for '{host}' to reboot...")
            time.sleep(interval)
    print(f"\033[91m[ERROR]           : Timeout while waiting for {host} to reboot.")
    sys.exit(1)


def is_valid_hostname(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        output_message(f"{value_str}' is NOT a string value.","e")

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        output_message(f"hostname has exceeded the masximum length of 253 characters.","e")

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            output_message(f"a label has exceeded the masximum length of 63 characters.","e")
        if not hostname_regex.match(label):  # Each label must match the regex
            output_message(f"a label contains invalid characters.","e")

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            output_message(f"{value_str}' contains invalid characters.","e")

    output_message(f"{value_str}' is a valid hostname.","s")


def check_valid_ip_address(which_ip,vlan=None):
    parts = which_ip.split('.')
    if len(parts) != 4:
        output_message(f"Invalid IP address '{which_ip}'. IP address should have exactly four parts.","E")

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                output_message(f"Invalid IP address '{which_ip}'. Each part should be between 0 and 255.","E")
        except ValueError:
            output_message(f"Invalid IP address '{which_ip}'. Each part should be an integer.","E")

    output_message(f"IP address '{which_ip}' is a valid ip-address.","s")

    if vlan:
        try:
            if int(vlan) == int(parts[2]):
                output_message(f"IP address 3rd octect '{parts[2]}' match VLAN ID '{vlan}'.","s")
            else:
                output_message(f"IP address 3rd octect '{parts[2]}' does not match VLAN ID '{vlan}'. Continuing...","w")

        except ValueError:
            output_message(f"Error occured checking VLAN.","E")


def check_netmask(value_string):
    try:
        netmask = int(value_string)
        if not netmask in range(23, 30):
            output_message(f"Invalid netmask '{value_string}'. Netmask is not a number between /24 and /29.", "E")
            return
    except ValueError:
        output_message(f"Invalid netmask '{value_string}'. Netmask is not a number value.","E")
        return

    output_message(f"Netmask '/{netmask}' is a valid netmask.","s")


def check_vlan(vlanid):
    try:
        if not int(vlanid) in range(2, 4095):
            output_message(f"Invalid VLAN '{vlanid}'. Vlan should be a number between 2 and 4094.","E")


    except ValueError:
        output_message(f"Invalid VLAN '{vlanid}'. Vlan id must be a number.", "E")

    output_message(f"VLAN id '{vlanid}' is a valid VLAN.", "s")


def change_remote_password(ssh, remote_user, current_password):

    # Change the password of ci_username
    try:
        # Prompt for the new password and store it in an environment variable
        new_password = getpass.getpass(f"Enter new password for user '{remote_user}': ")
        if not new_password:
            output_message("New password value is not set", "e")
        # Construct the command to change the password
        # Make sure to properly format the string and include the environment variable correctly
        sudo_command = f"echo {current_password} | sudo -S -p '' bash -c \"echo '{remote_user}:{new_password}' | chpasswd\""

        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            output_message(f"Failed to change password on {remote_user}: {error_output}.", "e")

        output_message(f"Password for user '{remote_user}' has been changed successfully.", "s")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Remove the NEW_PASSWORD from environment variables
        new_password = ""


def output_message(message=None, type=None):
    # Set pre_message to the correct prefix based on 'type'
    if type == "s" or type == "S":
        pre_message = "[✓] "
        color = '\033[32m'
    elif type == "i" or type == "I":
        pre_message = "[ ] "
        color = '\033[32m'
    elif type == "w" or type == "W":
        pre_message = "[*] "
        color = '\033[33m'
    elif type == "e" or type == "E":
        pre_message = "[x] "
        color = '\033[31m'
    elif type == "h" or type == "H":
        pre_message = ""
        color = '\033[0m'
        if message:
            message = message.upper()
            if len(message) < 78:
                blanks = 78 - len(message)
                left_padding = blanks // 2
                right_padding = blanks - left_padding
                heading = "-" + ' ' * left_padding + message + ' ' * right_padding + "-"
            else:
                heading = message[:78]
        else:
            heading = "-" * 80
        message = heading
    else:
        color = '\033[0m'
        if message:
            pre_message = "[?] "
        else:
            pre_message = ""

    reset = '\033[0m'

    if not message:
        message = "-" * 80

    # Now print the formatted message
    print(f"{color}{pre_message}{message}{reset}")
    if type == "e" or type == "E":
        message = "-" * 80
        print(f"{message}")
        sys.exit(1)


def validate_boolean(value, field_name):
    if not isinstance(value, bool):
        output_message(f"'{field_name}' must be a boolean (true/false)", "e")
        return False
    return True


def check_parameters(config, mandatory_keys, optional_keys):
    allowed_keys = set(mandatory_keys.keys()).union(optional_keys.keys())
    errors = []

    try:
        # Check for invalid keys in the JSON
        for key in config.keys():
            if key not in allowed_keys:
                errors.append(f"Invalid key '{key}' found in JSON configuration.")

        # Check for mandatory keys and sub-keys
        for key, sub_key in mandatory_keys.items():
            if key not in config:
                errors.append(f"Missing mandatory key '{key}' in JSON configuration.")
            elif sub_key not in config[key]:
                errors.append(f"Missing mandatory sub-key '{sub_key}' in '{key}' object.")
            elif not validate_boolean(config[key].get("allow_blank", None), f"{key}.allow_blank"):
                errors.append(f"Invalid boolean value for '{key}.allow_blank'.")
            elif not validate_boolean(config[key].get("allow_spaces", None), f"{key}.allow_spaces"):
                errors.append(f"Invalid boolean value for '{key}.allow_spaces'.")

        # Check for 'comment' key in each object, if required
        for key, obj in config.items():
            if "comment" not in obj:
                errors.append(f"'{key}' is missing 'comment' key.")

        # Output all errors if found
        if errors:
            for error in errors:
                output_message(f"{error}", "e")

        output_message(f"All parameters are structured correctly", "s")

    except Exception as e:
        output_message(f"Error while validating the structure in JSON file: {e}", "e")


def check_values(config, integer_keys=None):
    errors = []

    for key, obj in config.items():
        first_key = next(iter(obj))
        first_value = obj[first_key]

        # Check if allow_blank is false and the value is empty (only for strings)
        if obj.get("allow_blank") is False and isinstance(first_value, str) and first_value == "":
            errors.append(f"'{first_key}' is blank but cannot be blank.")

        # Check if allow_spaces is false and the value contains spaces (only for strings)
        if obj.get("allow_spaces") is False and isinstance(first_value, str) and " " in first_value:
            errors.append(f"'{first_key}' contains spaces but cannot have spaces.")

        # Check if value should be an integer, allowing strings that represent integers
        if integer_keys and key in integer_keys:
            if not isinstance(first_value, int):
                if isinstance(first_value, str):
                    try:
                        # Try to convert the string to an integer
                        int(first_value)
                    except ValueError:
                        errors.append(f"'{first_key}' should be an integer, but found non-integer value: '{first_value}'.")
                else:
                    errors.append(f"'{first_key}' should be an integer, but found type '{type(first_value).__name__}'.")

    # Output any errors found
    if errors:
        for error in errors:
            output_message(f"{error}", "e")

    output_message(f"All values are the correct type", "s")


def check_if_id_in_use(ssh, pve_id):
    command = f"qm list | awk '{{print $1}}' | grep -q '^{pve_id}$' && echo 'in_use' || echo 'not_in_use'"
    result = execute_ssh_command(ssh, command, f"Unable to query ID {pve_id} on proxmox host.")
    """Check if TEMPLATE_ID is already in use on the Proxmox host"""
    #stdin, stdout, stderr = ssh.exec_command(f"qm list | awk '{{print $1}}' | grep -q '^{template_id}$' && echo 'in_use' || echo 'not_in_use'")
    #result = stdout.read().decode().strip()
    if result == "in_use":
        return True
    else:
        return False


def get_status_info(search_string, scr_string):
    pattern = rf'{search_string}:\s*(.+)'
    match = re.search(pattern, scr_string)
    if match:
        search_string_value = match.group(1).strip()
    else:
        search_string_value = None
    return search_string_value


def get_config_info(search_string, scr_string):
    pattern = rf'{search_string}=(.*?)(?:,|$)'
    # rf'{search_string}=': Look for the key followed by =.
    # (.*?): Capture everything lazily (up to the
    # next comma or end of string).
    # (?:,|$): Stop at the next comma or the end of the string.
    match = re.search(pattern, scr_string)
    if match:
        search_string_value = match.group(1).strip()
    else:
        search_string_value = None
    return search_string_value