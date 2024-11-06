#!/usr/bin/env python3

import os
import json
import sys
import time
import paramiko

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from lib import json_test
from const.host_const import MANDATORY_KEYS, OPTIONAL_KEYS, INTEGER_KEYS

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip"),
        "pve_name": config.get("PVE_NAME").get("hostname"),
        "pve_domain": config.get("PVE_DOMAIN").get("domain_string"),
        "pve_sshkey": config.get("PVE_SSHKEY").get("publickey"),
        "pve_iso": config.get("PVE_ISO").get("urls")
    }

def add_snippets_folder(ssh, values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")

    # Define the commands
    command = "if [ ! -d '/var/lib/vz/snippets' ]; then mkdir /var/lib/vz/snippets; fi"
    functions.execute_ssh_command(ssh, command, f"Failed to create snippets folder.")
    print(f"\033[92m[SUCCESS]         : Snippets folder created or already exists on {pve_hostip}.")

def check_hostname(ssh, values):
    pve_hostname = values.get("pve_name")
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    pve_domain = values.get("pve_domain")
    max_wait_time = 300  # max wait time in seconds
    check_interval = 10  # time interval between retries in seconds
    total_waited = 0

    print(f"\033[92m[INFO]            : Expected hostname '{pve_hostname}'.")
    """Check the hostname of the Proxmox host via SSH using key authentication."""
    try:
        # Get current hostname
        command = f"hostname"
        current_hostname = functions.execute_ssh_command(ssh, command, f"Failed to get current hostname from {pve_hostip}")
        print(f"\033[92m[INFO]            : Current hostname '{current_hostname}'.")

        if current_hostname == pve_hostname:
            print(f"\033[92m[SUCCESS]         : Hostname matches the expected value.")
        else:
            print(f"\033[93m[INFO]            : Hostname mismatch! Expected '{pve_hostname}', but got '{current_hostname}'.")
            fqdn = f"{pve_hostname}.{pve_domain}"

            # Check if Proxmox node is empty
            command = (
                f"[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/lxc 2>/dev/null)\" ] && "
                f"[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/qemu-server 2>/dev/null)\" ]"
            )
            node_status = functions.execute_ssh_command(ssh, command, f"Failed to check if node is empty on {pve_hostip}")

            if node_status == "":
                print(f"\033[92m[INFO]            : Proxmox node is empty. Proceeding with hostname change.")

                # Perform the hostname change on the remote host
                command = f"""
                echo "{pve_hostname}" > /etc/hostname
                sed -i "/{current_hostname}/d" /etc/hosts
                echo "{pve_hostip} {fqdn} {pve_hostname}" >> /etc/hosts
                hostnamectl set-hostname "{pve_hostname}"
                reboot
                """
                functions.execute_ssh_command(ssh, command, f"Failed to change hostname on {pve_hostip}")
                print(f"\033[92m[SUCCESS]         : Hostname on {pve_hostip} has been changed from {current_hostname} to {fqdn}")

                # Close the SSH connection because the host is going down for reboot
                ssh.close()

                # Wait for 60 seconds before attempting to reconnect
                time.sleep(10)

                # Attempt to reconnect after reboot
                print(f"\033[92m[INFO]            : Waiting for {pve_hostip} to reboot...")
                ssh_up = None

                while total_waited < max_wait_time:
                    try:
                        # Initialize a new SSH client instance for each retry
                        ssh_up = paramiko.SSHClient()
                        ssh_up.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        # Try to connect with a timeout of 10 seconds
                        ssh_up.connect(hostname=pve_hostip, username=pve_username, timeout=10)

                        # Once connected, validate the hostname again
                        command = "hostname"
                        stdin, stdout, stderr = ssh_up.exec_command(command)
                        output = stdout.read().decode('utf-8').strip()
                        error_output = stderr.read().decode('utf-8').strip()

                        if error_output:
                            print(f"\033[93m[INFO]            : {pve_hostip} is not ready - retrying in {check_interval} sec.")
                            total_waited += check_interval
                            time.sleep(check_interval)
                            continue

                        if output == pve_hostname:
                            print(f"\033[92m[SUCCESS]         : {pve_hostip} now has hostname '{output}'.")
                            ssh_up.close()
                            return output
                        else:
                            print(f"\033[91m[ERROR]           : Hostname was not changed successfully.")
                            total_waited += check_interval
                            time.sleep(check_interval)

                    except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.SSHException, TimeoutError):
                        # Handle exception when connection fails
                        print(f"\033[93m[INFO]            : Host is still rebooting or connection failed, retrying in {check_interval} seconds...")
                        total_waited += check_interval
                        time.sleep(check_interval)

                    except Exception as e:
                        print(f"\033[91m[ERROR]           : Exception occurred: {e}, retrying...")
                        total_waited += check_interval
                        time.sleep(check_interval)

                    finally:
                        # Always close the ssh_up instance if it was opened
                        if ssh_up:
                            ssh_up.close()

                # If max wait time is exceeded
                print(f"\033[91m[ERROR]           : Failed to reconnect within {max_wait_time} seconds.")
                sys.exit(1)

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to set hostname: {e}")
        sys.exit(1)

def configure_sshd(ssh, values):
    # Set SSHD_CONFIG setting on VM
    for iteration in range(2):
        conf_file_dir = []
        conf_files = []
        config_include = False
        try:
            # Step 1: Gather list of configuration files
            # Check if config_file has include statements to other *.conf files
            for conf_file in SSHD_CONFIG:
                command = f"cat {conf_file}"
                stdin, stdout, stderr = ssh.exec_command(command)
                for line_number, line in enumerate(stdout, start=1):
                    if line.startswith(SSHD_SEARCHSTRING):
                        print(f"\033[92m[INFO]            : In {conf_file} found '{SSHD_SEARCHSTRING}' at the beginning of line {line_number}: {line.strip()}")
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
                    print(f"\033[93m[INFO]            : '{param}' is missing in all configuration files.")

            # Remove the verified parameters from params_to_add
            for verified_param in params_no_change:
                if verified_param in params_to_add:
                    del params_to_add[verified_param]

            # Remove the parameters that need modification from params_to_add
            for verified_param in params_to_change:
                if verified_param in params_to_add:
                    del params_to_add[verified_param]

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
                local_sshd_customfile = os.path.join(include_dir, os.path.basename(SSHD_CUSTOMFILE))

                if local_sshd_customfile not in SSHD_CONFIG:
                    command = f"touch {local_sshd_customfile}"
                    functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to touch {local_sshd_customfile}")
                    command = f"chmod 644 {local_sshd_customfile}"
                    functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to change permissions on {local_sshd_customfile}")
                    print(f"\033[92m[SUCCESS]         : Successfully created {local_sshd_customfile}")

                if os.path.dirname(local_sshd_customfile) == os.path.dirname(SSHD_CONFIG[0]):
                    command = f"echo Include {local_sshd_customfile} >> {SSHD_CONFIG[0]}"
                    functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to include {local_sshd_customfile} in {SSHD_CONFIG[0]}")
                    print(f"\033[92m[SUCCESS]         : Successfully included {local_sshd_customfile} in {SSHD_CONFIG[0]}")

                for param, expected_value in params_to_add.items():
                    command = f"echo {param} {expected_value} >> {local_sshd_customfile}"
                    functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to add paramter: {param} {expected_value} to {local_sshd_customfile}")
                    print(f"\033[92m[SUCCESS]         : Successfully added paramter: {param} {expected_value} to {local_sshd_customfile}")

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
                                functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to modify paramter: {param} {expected_value} in {path_value}")
                                print(f"\033[92m[SUCCESS]         : Successfully modified paramter: {param} {expected_value} in {path_value}")

        except Exception as e:
            print(f"An error occurred: {e}")

        finally:
            command = f"systemctl restart ssh"
            functions.execute_ssh_sudo_command(ssh, "CI_PASSWORD", command, f"Failed to restart SSH service")
            print(f"\033[92m[SUCCESS]         : Successfully restarted SSH service")

        if iteration == 0:
            print(f"\033[92m[INFO]            : Waiting for 5 seconds before running iteration 2")
            time.sleep(5)

    print(f"\033[92m[SUCCESS]         : sshd_config has the exoected configuration")












# DEBUG
config_file = "/home/nije/json-files/test.json"

#config_file = sys.argv[1]
script_directory = os.path.dirname(os.path.abspath(__file__))
print("-------------------------------------------")
print(f"Parameter filename: {config_file}")
print(f"Script directory  : {script_directory}")
print("-------------------------------------------")
print("")
print("-------------------------------------------")
print("--        Validate JSON structure        --")
print("-------------------------------------------")

config = load_config(config_file)
values = get_json_values(config)
# Use json_test to validate JSON structure
json_test.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

print("-------------------------------------------")
print("--          Validate JSON values         --")
print("-------------------------------------------")
# Validate JSON values to ensure proper types
json_test.check_values(config, integer_keys=INTEGER_KEYS)

print("-------------------------------------------")
print("--        Configure PROXMOX host         --")
print("-------------------------------------------")

# Establish SSH connection to Proxmox server
ssh = functions.ssh_connect(values.get("pve_host"), values.get("pve_user"))
add_snippets_folder(ssh, values)
check_hostname(ssh,values)
ssh = functions.ssh_connect(values.get("pve_host"), values.get("pve_user"))

ssh.close()

functions.end_output_to_shell()