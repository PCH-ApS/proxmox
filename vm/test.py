#!/usr/bin/env python3

import sys
import os

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from const.vm_const import SSH_CONST, SSHD_CONFIG, SSHD_SEARCHSTRING, SSHD_CUSTOMFILE

ipaddress = "192.168.254.3"
ci_username = "pch"
#ci_password = os.getenv("CI_PASSWORD")  # Retrieve the password from an environment variable

conf_file_dir = []
conf_files = []
config_include = False

# Connect to the SSH server
ssh = functions.ssh_connect(ipaddress, ci_username)

try:
    # Step 1: Gather list of configuration files
    # Check if config_file has include statements to other *.conf files
    for conf_file in SSHD_CONFIG:
        command = f"cat {conf_file}"
        stdin, stdout, stderr = ssh.exec_command(command)
        for line_number, line in enumerate(stdout, start=1):
            if line.startswith(SSHD_SEARCHSTRING):
                print(f"\033[93m[INFO]            : Found '{SSHD_SEARCHSTRING}' at the beginning of line {line_number}: {line.strip()}")
                config_include = True
                elements = line.split()
                for element in elements:
                    if element.startswith("/"):
                        if "*" in element:
                            conf_file_dir.append(element)
                        else:
                            SSHD_CONFIG.append(element)

    # Find all files matching the pattern specified in include statements
    for pattern in conf_file_dir:
        command = f"ls {pattern} 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(command)
        matched_files = stdout.read().decode().splitlines()
        conf_files.extend(matched_files)

    for file in conf_files:
            SSHD_CONFIG.append(file)

    # Print total found configuration files
    print(f"\033[93m[INFO]            : Found {len(SSHD_CONFIG)} sshd config files")

    # Step 2: Run through all files found to check if parameters have been set
    params_no_change = {}  # Tracks parameters that are set correctly
    params_to_add = SSH_CONST.copy()  # Tracks parameters that are missing
    params_to_change = {}  # Tracks parameters that need to be changed

        # Check each parameter in every configuration file
    for param, expected_value in SSH_CONST.items():
        param_found = False  # Track if parameter was found in any file
        for conf_file in SSHD_CONFIG:
            command = f"cat {conf_file}"
            stdin, stdout, stderr = ssh.exec_command(command)
            for line_number, line in enumerate(stdout, start=1):
                if line.startswith(param):
                    param_found = True
                    if expected_value in line:
                        params_no_change[param] = expected_value
                    else:
                        params_to_change[param] = {
                            "expected_value": expected_value,
                            "conf_file": conf_file
                        }
                    #break  # Stop searching in the current file once parameter is found

        if not param_found:
            # Parameter was not found in any of the configuration files
            print(f"\033[91m[WARNING]         : '{param}' is missing in all configuration files.")

    # Remove the verified parameters from params_to_add
    for verified_param in params_no_change:
        if verified_param in params_to_add:
            del params_to_add[verified_param]

    # Remove the parameters that need modification from params_to_add
    for verified_param in params_to_change:
        if verified_param in params_to_add:
            del params_to_add[verified_param]

    # Debug information - to be removed
    print(f"Parameters that are correct: {params_no_change}")
    print(f"Parameters that must be changes: {params_to_change}")
    print(f"Parameters that must be added: {params_to_add}")


    if len(params_to_add) > 0:
        # Add the parameters that are completly missing
        # Use the parth from first found include in conf_file_dir for SSHD_CUSTOMFILE filename
        # and if no Include is found then use the path of the initial SSHD_CONFIG file for the SSHD_CUSTOMFILE filename
        if conf_file_dir:
            # Use the directory from the first Include found as the target directory for the custom file
            include_dir = os.path.dirname(conf_file_dir[0])
        else:
            # Use the directory of the first SSHD_CONFIG file as the fallback
            include_dir = os.path.dirname(SSHD_CONFIG[0])

        # SSHD_CUSTOMFILE = f"{include_dir}{SSHD_CUSTOMFILE}"
        SSHD_CUSTOMFILE = os.path.join(include_dir, os.path.basename(SSHD_CUSTOMFILE))

        if not SSHD_CUSTOMFILE in SSHD_CONFIG:
            command = f"touch {SSHD_CUSTOMFILE}"
            functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to touch {SSHD_CUSTOMFILE}")
            command = f"chmod 644 {SSHD_CUSTOMFILE}"
            functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to change permissions on {SSHD_CUSTOMFILE}")
            command = f"echo Include {SSHD_CUSTOMFILE} >> {SSHD_CONFIG[0]}"
            functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to {SSHD_CUSTOMFILE} in {SSHD_CONFIG[0]}")

        for param, expected_value in params_to_add.items():
            command = f"echo {param} {expected_value} >> {SSHD_CUSTOMFILE}"
            functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to add paramter: {param} {expected_value} to {SSHD_CUSTOMFILE}")

    if len(params_to_change) > 0:
        for param, values in params_to_change.items():
            expected_value = values["expected_value"]
            path_value = values["conf_file"]
            param_found = False  # Track if parameter was found in any file
            command = f"cat {path_value}"
            stdin, stdout, stderr = ssh.exec_command(command)
            for line_number, line in enumerate(stdout, start=1):
                if line.startswith(param):
                    param_found = True
                    if param in line:
                        command = f"sed -i 's/^{param} .*/{param} {expected_value}/' {path_value}"
                        functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to add paramter: {param} {expected_value} to {SSHD_CUSTOMFILE}")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    #ssh.close()
    print("SSH connection closed")
    ssh.close()
