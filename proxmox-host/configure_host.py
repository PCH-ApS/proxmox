#!/usr/bin/env python3

import os
import json
import sys
import time
import paramiko
import getpass

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from lib import json_test
from const.host_const import MANDATORY_KEYS, OPTIONAL_KEYS, INTEGER_KEYS, SSH_CONST, SSHD_CONFIG, SSHD_SEARCHSTRING, SSHD_CUSTOMFILE

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

                # Attempt to reconnect after reboot
                print(f"\033[92m[INFO]            : Waiting for {pve_hostip} to reboot...")
                ssh_up = None
                time.sleep(10)

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
                    functions.execute_ssh_command(ssh, command, f"Failed to touch {local_sshd_customfile}")
                    command = f"chmod 644 {local_sshd_customfile}"
                    functions.execute_ssh_command(ssh, command, f"Failed to change permissions on {local_sshd_customfile}")
                    print(f"\033[92m[SUCCESS]         : Successfully created {local_sshd_customfile}")

                if os.path.dirname(local_sshd_customfile) == os.path.dirname(SSHD_CONFIG[0]):
                    command = f"echo Include {local_sshd_customfile} >> {SSHD_CONFIG[0]}"
                    functions.execute_ssh_command(ssh, command, f"Failed to include {local_sshd_customfile} in {SSHD_CONFIG[0]}")
                    print(f"\033[92m[SUCCESS]         : Successfully included {local_sshd_customfile} in {SSHD_CONFIG[0]}")

                for param, expected_value in params_to_add.items():
                    command = f"echo {param} {expected_value} >> {local_sshd_customfile}"
                    functions.execute_ssh_command(ssh, command, f"Failed to add paramter: {param} {expected_value} to {local_sshd_customfile}")
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
                                functions.execute_ssh_command(ssh, command, f"Failed to modify paramter: {param} {expected_value} in {path_value}")
                                print(f"\033[92m[SUCCESS]         : Successfully modified paramter: {param} {expected_value} in {path_value}")

        except Exception as e:
            print(f"An error occurred: {e}")

        finally:
            command = f"systemctl restart ssh"
            functions.execute_ssh_command(ssh, command, f"Failed to restart SSH service")
            print(f"\033[92m[SUCCESS]         : Successfully restarted SSH service")

        if iteration == 0:
            print(f"\033[92m[INFO]            : Waiting for 5 seconds before running iteration 2")
            time.sleep(5)

    print(f"\033[92m[SUCCESS]         : sshd_config has the exoected configuration")

def set_pve_no_subscription(ssh, values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")

    """Check and modify the pve_no_subscription setting."""
    try:
        # Step 1: Check if the pve-no-subscription repository is enabled or commented
        check_repo_cmd = 'grep -q "^deb .*pve-no-subscription" /etc/apt/sources.list && echo "enabled" || grep -q "^# deb .*pve-no-subscription" /etc/apt/sources.list && echo "commented" || echo "not_found"'
        stdin, stdout, stderr = ssh.exec_command(check_repo_cmd)

        result = stdout.read().decode().strip()

        if result == "enabled":
            print("\033[92m[INFO]            : pve-no-subscription repository is already enabled.")

        elif result == "commented":
            print("\033[91m[INFO]            : pve-no-subscription repository is found but not enabled. Enabling it now...")
            # Step 2: Enable the pve-no-subscription repository (uncomment it)
            enable_repo_cmd = "sed -i 's/^# deb \\(.*pve-no-subscription\\)/deb \\1/' /etc/apt/sources.list"
            ssh.exec_command(enable_repo_cmd)
            print(f"\033[92m[SUCCESS]         : pve-no-subscription repository has been enabled.")

        elif result == "not_found":
            print("\033[91m[INFO]            : pve-no-subscription repository not found. Adding it now...")
            # Step 3: Add the pve-no-subscription repository to sources.list
            add_repo_cmd = 'echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" | tee -a /etc/apt/sources.list > /dev/null'
            ssh.exec_command(add_repo_cmd)
            print(f"\033[92m[SUCCESS]         : pve-no-subscription repository has been added to /etc/apt/sources.list.")

        # Step 4: Check and disable enterprise repository if not already disabled
        check_enterprise_repo_cmd = 'grep -q "^deb .*bookworm pve-enterprise" /etc/apt/sources.list.d/pve-enterprise.list && echo "enabled" || echo "disabled"'
        stdin, stdout, stderr = ssh.exec_command(check_enterprise_repo_cmd)
        enterprise_result = stdout.read().decode().strip()

        if enterprise_result == "enabled":
            print("\033[91m[INFO]            : Enterprise repository is enabled. Disabling it now by commenting it out...")
            disable_enterprise_repo_cmd = r"sed -i 's/^\(deb .*bookworm pve-enterprise\)/# \1/' /etc/apt/sources.list.d/pve-enterprise.list"
            ssh.exec_command(disable_enterprise_repo_cmd)
            print(f"\033[92m[SUCCESS]         : Enterprise repository has been disabled by commenting it out.")
        else:
            print("\033[92m[INFO]            : Enterprise repository is already disabled.")

        # Step 5: Comment out Ceph-related entries in ceph.list
        check_ceph_list_cmd = 'grep -q "^deb .*ceph-quincy bookworm enterprise" /etc/apt/sources.list.d/ceph.list && echo "enabled" || echo "disabled"'
        stdin, stdout, stderr = ssh.exec_command(check_ceph_list_cmd)
        ceph_list_result = stdout.read().decode().strip()

        if ceph_list_result == "enabled":
            print("\033[91m[INFO]            : ceph.list found. Commenting out ceph-quincy, bookworm, or enterprise entries...")
            comment_ceph_entries_cmd = r"sed -i 's/^\(deb .*bookworm enterprise\)/# \1/' /etc/apt/sources.list.d/ceph.list"
            ssh.exec_command(comment_ceph_entries_cmd)
            print(f"\033[92m[SUCCESS]         : Ceph-related entries have been commented out in ceph.list.")
        else:
            print("\033[92m[INFO]            : ceph.list is already disabled.")

        # Step 6: Apply pve-no-subscription patch
        print("\033[92m[INFO]            : Attempting pve-no-subscription patch...")

        file_path = '/usr/share/perl5/PVE/API2/Subscription.pm'
        find_str = 'NotFound'
        replace_str = 'Active'

        # Check if the file exists
        check_file_cmd = f'test -f "{file_path}" && echo "exists" || echo "not_exists"'
        stdin, stdout, stderr = ssh.exec_command(check_file_cmd)
        file_exists = stdout.read().decode().strip()

        if file_exists == "not_exists":
            print(f"\033[91m[ERROR]           : {file_path} does not exist! Are you sure this is PVE?")
            ssh.close()
            sys.exit(1)
        else:
            # Check if the file contains 'NotFound'
            check_find_cmd = f'grep -i "{find_str}" "{file_path}" && echo "found" || echo "not_found"'
            stdin, stdout, stderr = ssh.exec_command(check_find_cmd)
            find_result = stdout.read().decode().strip()

            if find_result == "not_found":
                print(f"\033[92m[INFO]            : PVE appears to be patched.")
            else:
                # Apply the patch (replace 'NotFound' with 'Active')
                print(f"\033[92m[INFO]            : Applying pve-no-subscription patch in {file_path}...")
                apply_patch_cmd = f'sed -i "s/{find_str}/{replace_str}/gi" "{file_path}"'
                ssh.exec_command(apply_patch_cmd)

                # Restart the services
                print(f"\033[92m[INFO]            : Restarting services...")
                ssh.exec_command('systemctl restart pvedaemon')
                ssh.exec_command('systemctl restart pveproxy')

                print(f"\033[92m[SUCCESS]         : Subscription updated from {find_str} to {replace_str}.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        sys.exit(1)

def download_iso(ssh, values):
    pve_iso_urls = values.get("pve_iso")  # Correct access to 'pve_iso' key

    if not pve_iso_urls:
        print(f"\033[91m[ERROR]           : No ISO URLs provided in the configuration file.")
        sys.exit(1)

    try:
        # Step 1: Ensure the directory exists
        print(f"\033[92m[INFO]            : Ensuring /var/lib/vz/template/iso exists on the remote host...")
        ssh.exec_command("mkdir -p /var/lib/vz/template/iso")

        # Step 2: Check if each ISO image already exists and download if not
        for url in pve_iso_urls:
            iso_filename = url.split('/')[-1]
            iso_filepath = f"/var/lib/vz/template/iso/{iso_filename}"

            # Check if the file already exists on the remote host
            check_file_cmd = f"test -f {iso_filepath} && echo 'exists' || echo 'not_exists'"
            stdin, stdout, stderr = ssh.exec_command(check_file_cmd)
            file_exists = stdout.read().decode().strip()

            if file_exists == "exists":
                print(f"\033[93m[INFO]            : {iso_filename} already exists, skipping download.")
            else:
                print(f"\033[92m[INFO]            : Downloading {iso_filename} to /var/lib/vz/template/iso...")

                # Execute wget and wait for it to complete
                download_cmd = f"wget -q -P /var/lib/vz/template/iso {url}"
                stdin, stdout, stderr = ssh.exec_command(download_cmd)

                # Wait for the command to complete and check if any errors occurred
                exit_status = stdout.channel.recv_exit_status()  # Wait for the command to finish
                if exit_status == 0:
                    print(f"\033[92m[SUCCESS]         : {iso_filename} has been successfully downloaded.")
                else:
                    error_message = stderr.read().decode().strip()
                    print(f"\033[91m[ERROR]           : Failed to download {iso_filename}. Error: {error_message}")

        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        sys.exit(1)

def change_remote_password(ssh, values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    """Change the password of a remote user on the Proxmox host."""
    new_password = getpass.getpass(f"Enter new password for '{pve_username}': ")
    if not new_password:
        print(f"\033[91m[ERROR]           : New password value is not set\033[0m")

    try:
        # Command to change the password on the remote host
        change_password_cmd = f'echo "{pve_username}:{new_password}" | chpasswd'

        # Execute the command
        print(f"\033[92m[INFO]            : Changing password on {pve_hostip}...")
        stdin, stdout, stderr = ssh.exec_command(change_password_cmd)

        # Wait for the command to finish and check for errors
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print(f"\033[92m[SUCCESS]         : Password for user {pve_username} on {pve_hostip} has been updated successfully.")
        else:
            error_message = stderr.read().decode().strip()
            print(f"\033[91m[ERROR]           : Failed to update password. Error: {error_message}")
            sys.exit(1)

        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to {pve_hostip}: {e}")
        sys.exit(1)

config_file = sys.argv[1]
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
configure_sshd(ssh, values)
set_pve_no_subscription(ssh, values)
download_iso(ssh, values)
change_remote_password(ssh, values)
ssh.close()

functions.end_output_to_shell()