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
            f"Connected to {host} as {username}.",
            "s"
        )
        return ssh

    except paramiko.AuthenticationException:
        output_message(
            f"Authentication failed when connecting to {host}.",
            "Please check your credentials.",
            "w"
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
            output_message(
                f"SWaiting for '{host}' to reboot...",
                "w"
            )
            time.sleep(interval)
    output_message(
        f"Timeout while waiting for {host} to reboot.",
        "e"
    )


def is_valid_hostname(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        output_message(
            f"{value_str}' is NOT a string value.",
            "e"
        )

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        message = (
            f"{value_str} exceedes the masximum "
            "length of 253 characters."
        )
        output_message(
            message,
            "e"
        )

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            message = (
                f"{value_str} exceeds the masximum length of 63 characters."
            )
            output_message(
                message,
                "e"
            )
        if not hostname_regex.match(label):  # Each label must match the regex
            message = (
                f"{value_str} contains invalid characters."
            )
            output_message(
                message,
                "e"
            )

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            output_message(
                f"{value_str}' contains invalid characters.",
                "e"
            )

    output_message(
        f"{value_str}' is a valid hostname.",
        "s"
    )


def check_valid_ip_address(which_ip, vlan=None):

    parts = which_ip.split('.')

    if len(parts) != 4:
        message = (
            f"Invalid IP address '{which_ip}'. "
            "IP address should have exactly four parts."
        )
        output_message(message, "E")

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                message = (
                    f"Invalid IP address '{which_ip}'. "
                    "Each part should be between 0 and 255."
                )
                output_message(message, "E")
        except ValueError:
            message = (
                f"Invalid IP address '{which_ip}'. "
                "Each part should be an integer."
            )
            output_message(message, "E")

    message = (
        f"IP address '{which_ip}' is a valid ip-address."
    )
    output_message(message, "s")

    if vlan:
        try:
            if int(vlan) == int(parts[2]):
                message = (
                    f"IP address 3rd octect '{parts[2]}' "
                    f"match VLAN ID '{vlan}'."
                )
                output_message(message, "s")
            else:
                message = (
                    f"IP address 3rd octect '{parts[2]}' does not "
                    f"match VLAN ID '{vlan}'. Continuing..."
                )
                output_message(message, "w")

        except ValueError:
            output_message("Error occured checking VLAN.", "E")


def check_netmask(value_string):
    try:
        netmask = int(value_string)
        if netmask not in range(23, 30):
            message = (
                f"Invalid netmask '{value_string}'. "
                "Netmask is not a number between /24 and /29."
            )
            return False, message

    except ValueError:
        message = (
            f"Invalid netmask '{value_string}'. Netmask is not a number value."
        )
        return False, message

    message = f"Netmask '/{netmask}' is valid."
    return True, message


def check_vlan(which_ip, vlan):

    parts = which_ip.split('.')

    if int(vlan) == int(parts[2]):
        message = (
            f"IP address 3rd octect '{parts[2]}' of {which_ip} "
            f"match VLAN ID '{vlan}'."
        )
        return True, message

    else:
        message = (
            f"IP address 3rd octect '{parts[2]}' of {which_ip} does not "
            f"match VLAN ID '{vlan}'. Continuing..."
        )
        return False, message


def change_remote_password(ssh, remote_user, current_password):

    # Change the password of ci_username
    try:
        # Prompt for the new password and store it in an environment variable
        message = (
            f"Enter new password for user '{remote_user}': "
        )
        new_password = getpass.getpass(message)

        if not new_password:
            output_message("New password value is not set", "e")

        # Construct the command to change the password
        # Make sure to properly format the string and
        # include the environment variable correctly
        sudo_command = (
            f"echo {current_password} | "
            "sudo -S -p '' bash -c \"echo "
            f"'{remote_user}:{new_password}' | chpasswd\""
        )

        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            message = (
                f"Failed to change password on {remote_user}: {error_output}."
            )
            output_message(message, "e")

        message = (
            f"Password for user '{remote_user}' has been changed."
        )
        output_message(message, "s")

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
                left = "-" + ' ' * left_padding
                right = ' ' * right_padding + "-"
                heading = (
                    f"{left}"
                    f"{message}"
                    f"{right}"
                )
            else:
                heading = message[:78]
        else:
            heading = "-" * 80
        message = heading
    else:
        color = '\033[0m'
        if message:
            pre_message = "-   "
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
                message = (
                    f"Invalid key '{key}' found in JSON configuration."
                )
                errors.append(message)

        # Check for mandatory keys and sub-keys
        for key, sub_key in mandatory_keys.items():
            if key not in config:
                errors.append(
                    f"Missing mandatory key '{key}'"
                    " in JSON configuration."
                )
            elif sub_key not in config[key]:
                errors.append(
                    f"Missing mandatory sub-key '{sub_key}'"
                    f" in '{key}' object."
                )
            elif not validate_boolean(
                config[key].get("allow_blank", None),
                f"{key}.allow_blank"
            ):
                errors.append(
                    f"Invalid boolean value for '{key}.allow_blank'."
                )
            elif not validate_boolean(
                config[key].get("allow_spaces", None),
                f"{key}.allow_spaces"
            ):
                errors.append(
                    f"Invalid boolean value for '{key}.allow_spaces'."
                )

        # Check for 'comment' key in each object, if required
        for key, obj in config.items():
            if "comment" not in obj:
                errors.append(f"'{key}' is missing 'comment' key.")

        # Output all errors if found
        if errors:
            for error in errors:
                output_message(f"{error}", "e")

        output_message("All parameters are structured correctly", "s")

    except Exception as e:
        message = (
            f"Error while validating the structure in JSON file: {e}"
        )
        output_message(message, "e")


def check_values(config, integer_keys=None):
    errors = []

    for key, obj in config.items():
        first_key = next(iter(obj))
        first_value = obj[first_key]

        # Check if allow_blank is false and
        # the value is empty (only for strings)
        if (
            obj.get("allow_blank") is False
            and isinstance(first_value, str)
            and first_value == ""
        ):
            errors.append(f"'{first_key}' is blank but cannot be blank.")

        # Check if allow_spaces is false and
        # the value contains spaces (only for strings)
        if (
            obj.get("allow_spaces") is False
            and isinstance(first_value, str)
            and " " in first_value
        ):
            errors.append(
                f"'{first_key}' contains spaces "
                "but cannot have spaces."
            )

        # Check if value should be an integer,
        # allowing strings that represent integers
        if integer_keys and key in integer_keys:
            if not isinstance(first_value, int):
                if isinstance(first_value, str):
                    try:
                        # Try to convert the string to an integer
                        int(first_value)
                    except ValueError:
                        errors.append(
                            f"'{first_key}' should be an integer, "
                            f"but found non-integer value: '{first_value}'."
                        )
                else:
                    errors.append(
                        f"'{first_key}' should be an integer, but found type "
                        f"'{type(first_value).__name__}'."
                    )

    # Output any errors found
    if errors:
        for error in errors:
            output_message(f"{error}", "e")

    output_message("All values are the correct type", "s")


def check_if_id_in_use(ssh, pve_id):
    command = (
        "qm list | "
        f"awk '{{print $1}}' | "
        f"grep -q '^{pve_id}$' && "
        "echo 'in_use' || echo 'not_in_use'"
    )
    message = (
        f"Unable to query ID {pve_id} on proxmox host."
    )
    result = execute_ssh_command(ssh, command, message)
    """Check if TEMPLATE_ID is already in use on the Proxmox host"""
    # stdin, stdout, stderr = ssh.exec_command(f"qm list
    # | awk '{{print $1}}' | grep -q '^{template_id}$'
    # && echo 'in_use' || echo 'not_in_use'")
    # result = stdout.read().decode().strip()
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


def integer_check(values, integers):
    errors = []

    for key in values:
        if key in integers:
            key_value = values.get(key)
            if not isinstance(key_value, int):
                errors.append(
                    f"'{key}' should be an integer, "
                    f"but found non-integer value: '{key_value}'."
                )

    if errors:
        for error in errors:
            output_message(f"{error}", "e")
    else:
        output_message("All integer values are correct", "s")


def check_bridge_exists(ssh, bridge):
    command = f"brctl show | grep -w '{bridge}'"
    result = execute_ssh_command(
        ssh,
        command,
        (
            f"Network bridge: {bridge} does not exist "
            "or is not active on the Proxmox host."
        )
    )

    if result:
        return True
    else:
        return False


def check_storage_exists(ssh, local_storage):
    stdin, stdout, stderr = ssh.exec_command(
        f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    )

    command = f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    result = execute_ssh_command(
        ssh,
        command,
        f"Storage: {local_storage} does NOT exist on the Proxmox host."
    )
    if result:
        return True
    else:
        return False


def check_valid_ip_address_v2(which_ip):

    parts = which_ip.split('.')

    if len(parts) != 4:
        message = (
            f"Invalid IP address '{which_ip}'. "
            "An IP address should have exactly four parts."
        )
        return False, message

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                message = (
                    f"Invalid IP address '{which_ip}'. "
                    "Each part should be between 0 and 255."
                )
                return False, message

        except ValueError:
            message = (
                f"Invalid IP address '{which_ip}'. "
                "Each part should be an integer."
            )
            return False, message

    message = (
        f"IP address '{which_ip}' is valid."
    )
    return True, message


def is_valid_hostname_v2(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        message = (
            f"{value_str}' is NOT a string value.")
        return False, message

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        message = (
            f"{value_str} exceedes the masximum "
            "length of 253 characters."
        )
        return False, message

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            message = (
                f"{label} exceeds the masximum length of 63 characters."
            )
            return False, message

        if not hostname_regex.match(label):  # Each label must match the regex
            message = (
                f"{label} contains invalid characters."
            )
            return False, message

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            message = (
                f"{value_str}' contains invalid characters."
            )
            return False, message

    message = (
        f"Hostname {value_str}' is a valid."
    )
    return True, message


def ssh_connect_v2(host, username, password=None, key_filename=None):
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
        message = f"Connected to {host} as {username}."
        return True, message, ssh

    except paramiko.AuthenticationException:
        message = (
            f"Authentication failed when connecting to {host}."
            "Please check your credentials."
        )
        return False, message, None

    except paramiko.SSHException as e:
        message = f"Unable to establish SSH connection to {host}: {e}"
        return False, message, None

    except Exception as e:
        message = f"Unexpected error while connecting to {host}: {e}"
        return False, message, None

    finally:
        if ssh and not ssh.get_transport():
            ssh.close()  # Ensure cleanup of uninitialized connections


def check_vlan_is_valid(vlanid):
    try:
        if not int(vlanid) in range(2, 4095):
            message = (
                f"Invalid VLAN: '{vlanid}'. Vlan should be a "
                "number between 2 and 4094."
            )
            return False, message

    except ValueError:
        message = (
            f"Invalid VLAN '{vlanid}'. Vlan id must be a number."
        )
        return False, message

    message = (
        f"VLAN id '{vlanid}' is valid."
    )
    return True, message


def execute_ssh_command_v2(ssh, command):
    """
    Execute a command over an SSH connection and return the results.

    Args:
        ssh: The SSH connection object.
        command: The command to execute.

    Returns:
        A tuple (stdout, stderr, exit_status).
        - stdout: The standard output of the command.
        - stderr: The error output of the command (if any).
        - exit_status: The exit status code of the command.
    """

    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode().strip()
    error_output = stderr.read().decode().strip()

    return output, error_output, exit_status


def test_ssh(timeout, host, username, password=None, keyfile=None):

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(
                hostname=host,
                username=username,
                password=password,
                timeout=timeout
            )
        elif keyfile:
            ssh.connect(
                hostname=host,
                username=username,
                key_filename=keyfile,
                timeout=timeout
            )
        else:
            ssh.connect(
                hostname=host,
                username=username,
                timeout=timeout
            )

        return False

    except TimeoutError:
        return True  # Connection timed out

    except paramiko.AuthenticationException:
        return "Authentication failed. Check credentials."

    except paramiko.SSHException as e:
        return f"SSH error: {e}"

    except Exception as e:
        return f"Unexpected error: {e}"


def list_config_files(ssh, SSHD_CONFIG, SSHD_SEARCHSTRING):
    """
    Identify SSHD configuration files, including included files
    and directories.

    Args:
        ssh: An active SSH connection.
        SSHD_CONFIG: The main SSHD configuration file.
        SSHD_SEARCHSTRING: String to search for included config files.

    Returns:
        tuple: (
        success_flag,
        message or list of SSHD configuration file paths
        ).
    """
    config_files = [SSHD_CONFIG]
    config_file_patterns = []

    try:
        command = f"cat {SSHD_CONFIG}"
        output, error_output, exit_status = execute_ssh_command_v2(
            ssh,
            command
            )
        if exit_status != 0:
            return False, f"Failed to read configuration file: {error_output}"
    except Exception as e:
        return False, f"Error: {str(e)}"

    for line in output.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith(SSHD_SEARCHSTRING):
            conf_elements = stripped_line.split()
            # Skip the 'Include' keyword
            for conf_element in conf_elements[1:]:
                if '*' in conf_element:  # Wildcard pattern
                    config_file_patterns.append(conf_element)
                elif '/' in conf_element:  # Direct file reference
                    config_files.append(conf_element)

    for pattern in config_file_patterns:
        try:
            command = f"ls {pattern} 2>/dev/null"
            output, error_output, exit_status = execute_ssh_command_v2(
                ssh,
                command
            )
            if exit_status != 0:
                continue  # Skip patterns that do not match any files
        except Exception as e:
            return False, f"Error expanding pattern {pattern}: {str(e)}"

        config_files.extend(output.splitlines())

    return True, config_files


def extract_active_parameters(ssh, config_files):
    """
    Extract active SSHD configuration parameters from the given config files.

    Args:
        ssh: An active SSH connection.
        config_files: List of SSHD config file paths.

    Returns:
        tuple: (success_flag, message or list of tuples with
        (parameter, value, file)).
    """
    all_params = []

    for file in config_files:
        try:
            command = f"cat {file}"
            output, error_output, exit_status = execute_ssh_command_v2(
                ssh,
                command
                )
            if exit_status != 0:
                message = (
                    f"Failed to read configuration file {file}:"
                    f"{error_output}"
                )
                return False, message
        except Exception as e:
            return False, f"Error reading {file}: {str(e)}"

        for line in output.splitlines():
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('#'):
                continue

            parts = stripped_line.split(None, 1)
            if len(parts) == 2:
                param, value = parts
                all_params.append((param, value.strip(), file))

    return True, all_params


def find_multiple_definitions(active_params):
    """
    Identify parameters that are defined multiple times in different files.

    Args:
        active_params: List of tuples containing (parameter, value, file).

    Returns:
        dict: A dictionary mapping parameters to a list of file paths where
        they appear multiple times.
    """
    param_occurrences = {}

    for param, value, file in active_params:
        if param not in param_occurrences:
            param_occurrences[param] = []
        param_occurrences[param].append((value, file))

    multi_defined = {
        param: occurrences for param,
        occurrences in param_occurrences.items()
        if len(occurrences) > 1
        }

    if len(multi_defined) == 0:
        return False, "No SSHD parameters defined multiple times"

    return True, multi_defined


def analyse_multiple_definitions(multi_defined, SSH_CONST, SSHD_CUSTOMFILE):
    parameters_to_comment_out = []
    parameters_to_add = {}
    parameters_to_change = {}

    for param, instances in multi_defined.items():
        desired_value = SSH_CONST.get(param)
        if desired_value is None:
            # Skip parameters not managed by SSH_CONST.
            continue

        # Separate instances based on whether they
        # belong to SSHD_CUSTOMFILE or not.
        custom_instances = [
            inst
            for inst in instances
            if inst[1] == SSHD_CUSTOMFILE
        ]
        other_instances = [
            inst
            for inst in instances
            if inst[1] != SSHD_CUSTOMFILE
        ]

        if not custom_instances:
            # Case: All definitions are outside SSHD_CUSTOMFILE.
            # Check if any instance is already correct.
            correct_instances = [
                inst
                for inst in other_instances
                if inst[0] == desired_value
            ]
            if correct_instances:
                # Keep the first correct instance, and mark
                # all others for commenting out.
                keep_instance = correct_instances[0]
                for inst in other_instances:
                    if inst != keep_instance:
                        parameters_to_comment_out.append(
                            (param, inst[0], inst[1])
                            )
            else:
                # No correct instance exists.
                # Comment out all current instances and
                # schedule adding the correct one.
                for inst in other_instances:
                    parameters_to_comment_out.append((param, inst[0], inst[1]))
                parameters_to_add[param] = desired_value
        else:
            # Case: At least one instance is in SSHD_CUSTOMFILE.
            # Check if any custom instance already has the desired value.
            correct_custom = [
                inst
                for inst in custom_instances
                if inst[0] == desired_value
            ]
            if correct_custom:
                # If a correct custom instance exists,
                # keep the first one and comment out the others.
                keep_instance = correct_custom[0]
                for inst in custom_instances:
                    if inst != keep_instance:
                        parameters_to_comment_out.append(
                            (param, inst[0], inst[1])
                        )
                for inst in other_instances:
                    parameters_to_comment_out.append(
                        (param, inst[0], inst[1])
                    )
            else:
                # None of the custom instances has the desired value.
                # Mark the first custom instance for change and
                # comment out any other occurrences.
                change_instance = custom_instances[0]
                parameters_to_change[param] = (
                    change_instance[0],
                    change_instance[1],
                    desired_value
                )
                for inst in custom_instances[1:]:
                    parameters_to_comment_out.append((param, inst[0], inst[1]))
                for inst in other_instances:
                    parameters_to_comment_out.append((param, inst[0], inst[1]))

    return parameters_to_comment_out, parameters_to_add


def comment_out_parameters(ssh, parameters_to_comment_out):
    """
    Comments out the specified parameter definitions in
    their respective configuration files on the remote system,
    adding a marker to indicate that the change was made by this script.

    Args:
        ssh: An active SSH connection.
        parameters_to_comment_out:
            A list of tuples (parameter, current_value, file_path) indicating
            which configuration lines to comment out.
            Example:
            [('PasswordAuthentication', 'yes', '/etc/ssh/sshd_config'), ...]

    Returns:
        tuple: (success_flag, message)
            success_flag:
            True if all modifications were attempted, False otherwise.
            message: A summary message or error details.
    """
    # Marker that will be added to commented out lines.
    marker = "[SCRIPT]"

    for param, current_value, file_path in parameters_to_comment_out:
        # Build a sed command that finds lines starting with optional
        # whitespace that are not already commented out,
        # contain the parameter name followed by one or more whitespace
        # characters and then the current value.
        # The substitution then prepends the line with "# [SCRIPT] "
        # so that the change is visible.
        sed_command = (
            f"sed -i '/^\\s*[^#]*\\b{param}\\b\\s\\+{current_value}\\b/"
            f"s/^/# {marker} /' {file_path}"
        )

        try:
            output, error_output, exit_status = execute_ssh_command_v2(
                ssh,
                sed_command
            )
            if exit_status != 0:
                message = (
                    f"Failed to comment out {param} with value "
                    f"'{current_value}' in {file_path}. Error: {error_output}"
                )
                return False, message

        except Exception as e:
            message = (
                f"Exception occurred while processing {param}"
                f" in {file_path}: {str(e)}"
            )
            return False, message
    message = "Multi defined parameters commented out successfully"
    return True, message


def get_missing_parameter(ssh, active_parameters, SSH_CONST):
    """
    Provided with active_parameters,
    verify that every parameter in SSH_CONST is present.
    return any missing parameter.

    Args:
        ssh: An active SSH connection.
        active_parameters:
            A list of tuples representing active parameter definitions.
            Each tuple is of the form: (parameter, value, file_path)

    Returns:
        tuple: (success_flag, message)
            success_flag:
                True if all missing parameters were processed
                    (or none were missing),
                False otherwise.
            message: A summary message indicating the outcome.
    """
    # List to store parameters that are missing.
    missing_parameters = {}

    # Check each desired parameter in SSH_CONST
    for param, desired_value in SSH_CONST.items():
        # Search in active_parameters for a matching parameter name.
        found = any(
            active_param
            for active_param in active_parameters
            if active_param[0] == param
        )
        if not found:
            missing_parameters[param] = desired_value

    if missing_parameters:
        message = (
            f"Missing SSHD parameters: "
            f"{', '.join(missing_parameters.keys())}."
        )
        return True, message, missing_parameters
    else:
        message = "No missing SSHD parameters."
        return False, message, missing_parameters


def check_custom_file(config_files, SSHD_CUSTOMFILE):
    """
    Example config_files:
    [
        '/etc/ssh/sshd_config',
        '/etc/ssh/sshd_config.d/98-automation.conf',
        '/etc/ssh/sshd_config.d/99-automation-default-config.conf'
    ]

    Example SSHD_CUSTOMFILE = "/99-automation-default-config.conf"

    check if SSHD_CUSTOMFILE exists in config_files
        if it does return the full path of SSHD_CUSTOMFILE

    """
    for file_path in config_files:
        if file_path.endswith(SSHD_CUSTOMFILE):
            return True, file_path

    return False, ""


def determine_custom_file_path(
        active_parameters,
        CONFIG,
        CUSTOMFILE
        ):

    """
    Determine the full path where CUSTOMFILE should be placed based on the
    active parameters.

    The logic is as follows:
    1. Search active_parameters
       (a list of tuples: (parameter, value, filepath))
       for an "Include" directive that appears in CONFIG.
    2. If no such Include directive is found, return (True, default_path)
       where:
         - default_path is CUSTOMFILE placed in the same directory as CONFIG.
         - True indicates that an Include statement must be added.
    3. If an Include directive is found:
         - If its value is a glob pattern
           (e.g. "/etc/ssh/sshd_config.d/*.conf"):
             * Extract the directory portion and the pattern.
             * If the pattern has an extension (like "*.conf")
               and the extension of CUSTOMFILE (via os.path.splitext) matches
               (or if no extension is enforced),
               return (False, path) where path is CUSTOMFILE placed in
               that directory.
             * Otherwise, fall back to default_path.
         - If its value ends with a slash, treat it as a directory and place
           CUSTOMFILE there.
         - Otherwise, if it's a direct file inclusion, return (False, value).

    Args:
        active_parameters (list): List of tuples (parameter, value, filepath).
        For example:
        [
          ('Include', '/etc/ssh/sshd_config.d/*.conf', '/etc/ssh/sshd_config'),
          ('PasswordAuthentication', 'no', '/etc/ssh/sshd_config'),
            ...
        ]
        CONFIG (str): Full path to the main SSHD configuration file
        (e.g. "/etc/ssh/sshd_config").
        CUSTOMFILE (str): The custom file specification
        (e.g. "/99-automation-default-config.conf").

    Returns:
        tuple: (need_include_statement, full_path)
            need_include_statement (bool):
                True if an Include statement must be added,
                False if an appropriate Include was found.
            full_path (str): The full path for CUSTOMFILE
            based on the above logic.
    """

    # Default: place CUSTOMFILE in the same directory as CONFIG.
    default_path = os.path.join(
        os.path.dirname(CONFIG),
        os.path.basename(CUSTOMFILE)
        )

    # Quickly test if an Include directive
    # exists in active_parameters for CONFIG.
    include_directive = None
    for param, value, filepath in active_parameters:
        if param == "Include" and filepath == CONFIG:
            include_directive = value
            break

    # If no Include directive is found,
    # return default path and flag that we need to add one.
    if include_directive is None:
        return True, default_path

    # Process the found Include directive.
    if "*" in include_directive:
        # Value is a glob pattern.
        include_dir = os.path.dirname(include_directive)
        # e.g., "*.conf"
        include_pattern = os.path.basename(include_directive)

        ext_filter = ""
        if include_pattern != "*" and "." in include_pattern:
            # e.g., "*.conf" -> ext_filter becomes ".conf"
            ext_filter = include_pattern.replace("*", "")

        # e.g., ".conf"
        custom_ext = os.path.splitext(os.path.basename(CUSTOMFILE))[1]
        if not ext_filter or custom_ext == ext_filter:
            return False, os.path.join(
                include_dir,
                os.path.basename(CUSTOMFILE)
            )
        else:
            return False, default_path
    else:
        # Not a glob pattern.
        if include_directive.endswith("/"):
            # Treat it as a directory.
            message = os.path.join(
                include_directive,
                os.path.basename(CUSTOMFILE)
            )
            return False, message
        else:
            # Direct file inclusion.
            return False, include_directive


def creste_custom_file(ssh, SSHD_CUSTOMFILE, owner, permissions):
    """
    Given the full path to the custom config file (SSHD_CUSTOMFILE),
    create the file (if it doesn't already exist), set its owner ex. root,
    and set its permissions ex. 644.

    Example SSHD_CUSTOMFILE:
        "/etc/ssh/sshd_config.d/99-automation-default-config.conf"
    """

    command = (
        f"touch {SSHD_CUSTOMFILE} && "
        f"chown {owner}:{owner} {SSHD_CUSTOMFILE} && "
        f"chmod {permissions} {SSHD_CUSTOMFILE}"
    )
    try:
        output, error_output, exit_status = execute_ssh_command_v2(
            ssh,
            command
        )
        if exit_status != 0:
            message = f"Error creating custom file: {error_output}"
            return False, message

    except Exception as e:
        message = f"Exception occurred: {str(e)}"
        return False, message

    message = f"Custom file created and configured: {SSHD_CUSTOMFILE}"
    return True, message


def add_missing_parameter(ssh, missing_parameters, SSHD_CUSTOMFILE):
    """
    Provided with missing_parameters, add them to SSHD_CUSTOMFILE

    Args:
        ssh: An active SSH connection.
        missing_parameters:
            A list of tuples representing missing parameter definitions.
            Each tuple is of the form: (parameter, value)
        SSHD_CUSTOMFILE:
            The file name in a included folder
            to which missing parameters should be added.

    Returns:
        tuple: (success_flag, message)
            success_flag:
                True if all missing parameters were processed
                False otherwise.
            message: A summary message indicating the outcome.
    """
    # Append any missing parameter lines to the SSHD_CUSTOMFILE.
    for param, value in missing_parameters.items():
        # Build the configuration line.
        line = f"{param} {value}"
        # The command appends the new line to SSHD_CUSTOMFILE.
        command = f"echo '{line}' >> {SSHD_CUSTOMFILE}"
        try:
            output, error_output, exit_status = execute_ssh_command_v2(
                ssh,
                command
            )
            if exit_status != 0:
                message = (
                    f"Failed to add parameter {param} to {SSHD_CUSTOMFILE}."
                    f" Error: {error_output}"
                )
                return False, message
        except Exception as e:
            message = (
                f"Exception occurred while adding {param} to "
                f"{SSHD_CUSTOMFILE}: {str(e)}"
            )
            return False, message

    if missing_parameters:
        message = (
            f"Added missing parameters to {SSHD_CUSTOMFILE}: "
            f"{', '.join(missing_parameters.keys())}"
        )
        return True, message, missing_parameters
    else:
        message = "No missing parameters to add."
        return False, message, missing_parameters
