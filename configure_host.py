#!/usr/bin/env python3
from lib import functions
from const.host_const import (
    MANDATORY_KEYS, OPTIONAL_KEYS,
    INTEGER_KEYS, SSH_CONST,
    SSHD_CONFIG, SSHD_SEARCHSTRING,
    SSHD_CUSTOMFILE, PVE_KEYFILE,
    SNIPPETS_FOLDER
)

import os
import json
import sys
import time
import paramiko
import getpass

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def load_config(config_file):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        functions.output_message(
            f"Error reading the configuration file: {e}",
            "w"
            )
        return None


def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip"),
        "pve_name": config.get("PVE_NAME").get("hostname"),
        "pve_domain": config.get("PVE_DOMAIN").get("domain_string"),
        "pve_sshkey": config.get("PVE_SSHKEY").get("publickey"),
        "pve_iso": config.get("PVE_ISO").get("urls"),
        "pve_changepwd": config.get("PVE_PWCHANGE").get("change_pwd")
    }


def add_snippets_folder(ssh, values):
    pve_hostip = values.get("pve_host")

    # Create the snippet folder on the Proxmox host
    snippets_dir = SNIPPETS_FOLDER
    command = (
            f'test -d "{snippets_dir}" && '
            'echo "exists" || echo "not_exists"'
        )
    result = functions.execute_ssh_command(ssh, command)

    if result == "not_exists":
        command = (
            f"mkdir {snippets_dir}"
        )
        functions.execute_ssh_command(
            ssh,
            command,
            "Failed to create snippets folder."
        )
        functions.output_message(
            f"Snippets folder created on {pve_hostip}.",
            "s"
        )

        functions.output_message(
            f"Snippets folder added to configuration on {pve_hostip}.",
            "s"
        )

    if result == "exists":
        functions.output_message(
            f"Snippets folder already exists on {pve_hostip}.",
            "i"
        )

    command = "pvesm set local --content iso,vztmpl,backup,snippets"
    functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to add snippets folder to configuration on {pve_hostip}."
    )


def check_hostname(ssh, values):
    pve_hostname = values.get("pve_name")
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    pve_domain = values.get("pve_domain")
    max_wait_time = 300  # max wait time in seconds
    check_interval = 10  # time interval between retries in seconds
    total_waited = 0

    try:
        command = "hostname"
        current_hostname = functions.execute_ssh_command(
            ssh,
            command,
            f"Failed to get current hostname from {pve_hostip}"
        )

        if current_hostname == pve_hostname:
            functions.output_message(
                "Hostname is correct.",
                "s"
            )
        else:
            functions.output_message(
                (
                    f"Hostname mismatch! Expected '{pve_hostname}', "
                    f"but got '{current_hostname}'."
                ),
                "w"
            )
            fqdn = f"{pve_hostname}.{pve_domain}"

            command = (
                f"[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/lxc "
                "2>/dev/null)\" ] && "
                f"[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/"
                "qemu-server 2>/dev/null)\" ]"
            )
            node_status = functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to check if node is empty on {pve_hostip}"
            )

            if node_status == "":
                functions.output_message(
                    "Proxmox node is empty. Proceeding with hostname change.",
                    "i"
                )

                # Perform the hostname change on the remote host
                command = f"""
                echo "{pve_hostname}" > /etc/hostname
                sed -i "/{current_hostname}/d" /etc/hosts
                echo "{pve_hostip} {fqdn} {pve_hostname}" >> /etc/hosts
                hostnamectl set-hostname "{pve_hostname}"
                reboot
                """
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"Failed to change hostname on {pve_hostip}"
                )
                functions.output_message(
                    (
                        f"Hostname on {pve_hostip} has been changed "
                        f"from {current_hostname} to {fqdn}"
                    ),
                    "s"
                )

                ssh.close()

                functions.output_message(
                    f"Waiting for {pve_hostip} to reboot...",
                    "i"
                )
                ssh_up = None
                time.sleep(10)

                while total_waited < max_wait_time:
                    try:
                        # Initialize a new SSH client instance for each retry
                        ssh_up = paramiko.SSHClient()
                        ssh_up.set_missing_host_key_policy(
                            paramiko.AutoAddPolicy()
                        )

                        ssh_up.connect(
                            hostname=pve_hostip,
                            username=pve_username,
                            timeout=1
                        )

                        command = "hostname"
                        stdin, stdout, stderr = ssh_up.exec_command(command)
                        output = stdout.read().decode('utf-8').strip()
                        error_output = stderr.read().decode('utf-8').strip()

                        if error_output:
                            functions.output_message(
                                f"{pve_hostip} is not ready - retrying in "
                                f"{check_interval} sec.",
                                "i"
                            )
                            total_waited += check_interval
                            time.sleep(check_interval)
                            continue

                        if output == pve_hostname:
                            functions.output_message(
                                f"{pve_hostip} now has hostname '{output}'.",
                                "s"
                            )
                            ssh_up.close()
                            return output

                        else:
                            functions.output_message(
                                "Hostname was not changed.",
                                "e"
                            )
                            total_waited += check_interval
                            time.sleep(check_interval)

                    except (
                        paramiko.ssh_exception.NoValidConnectionsError,
                        paramiko.ssh_exception.SSHException,
                        TimeoutError
                    ):
                        functions.output_message(
                            "Host is still rebooting or connection failed, "
                            f"retrying in {check_interval} seconds...",
                            "i"
                        )
                        total_waited += check_interval
                        time.sleep(check_interval)

                    except Exception as e:
                        functions.output_message(
                            f"Exception occurred: {e}, retrying...",
                            "w"
                        )
                        total_waited += check_interval
                        time.sleep(check_interval)

                    finally:
                        # Always close the ssh_up instance if it was opened
                        if ssh_up:
                            ssh_up.close()

                # If max wait time is exceeded
                functions.output_message(
                    f"Failed to reconnect within {max_wait_time} seconds.",
                    "e"
                )

    except Exception as e:
        functions.output_message(
            f"Failed to set hostname: {e}",
            "e"
        )


def configure_sshd(ssh, values):
    # Set SSHD_CONFIG setting on VM
    for iteration in range(2):
        conf_file_dir = []
        conf_files = []
        try:
            # Step 1: Gather list of configuration files
            # Check if config_file has include statements to other *.conf files
            for conf_file in SSHD_CONFIG:
                command = f"cat {conf_file}"
                stdin, stdout, stderr = ssh.exec_command(command)
                for line_number, line in enumerate(stdout, start=1):
                    if line.startswith(SSHD_SEARCHSTRING):
                        elements = line.split()
                        for element in elements:
                            if element.startswith("/"):
                                if "*" in element:
                                    conf_file_dir.append(element)
                                else:
                                    SSHD_CONFIG.append(element)

            # Find all files matching the pattern
            # specified in include statements
            for pattern in conf_file_dir:
                command = f"ls {pattern} 2>/dev/null"
                stdin, stdout, stderr = ssh.exec_command(command)
                matched_files = stdout.read().decode().splitlines()
                conf_files.extend(matched_files)

            for file in conf_files:
                SSHD_CONFIG.append(file)

            # Step 2: Run through all files found to
            # check if parameters have been set
            params_no_change = {}
            params_to_add = SSH_CONST.copy()
            params_to_change = {}

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

                if not param_found:
                    # Parameter was not found in any of the configuration files
                    functions.output_message(
                        f"'{param}' is missing in all configuration files.",
                        "i"
                    )

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
                # Use the parth from first found include in conf_file_dir
                # for SSHD_CUSTOMFILE filename and if no Include is found
                # then use the path of the initial SSHD_CONFIG file for
                # the SSHD_CUSTOMFILE filename
                if conf_file_dir:
                    # Use the directory from the first Include found
                    # as the target directory for the custom file
                    include_dir = os.path.dirname(conf_file_dir[0])
                else:
                    # Use the directory of the first SSHD_CONFIG file
                    # as the fallback
                    include_dir = os.path.dirname(SSHD_CONFIG[0])

                # SSHD_CUSTOMFILE = f"{include_dir}{SSHD_CUSTOMFILE}"
                local_sshd_customfile = os.path.join(
                    include_dir,
                    os.path.basename(SSHD_CUSTOMFILE)
                )

                if local_sshd_customfile not in SSHD_CONFIG:
                    command = f"touch {local_sshd_customfile}"
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        f"Failed to touch {local_sshd_customfile}"
                    )

                    command = f"chmod 644 {local_sshd_customfile}"
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            f"Failed to change permissions on "
                            f"{local_sshd_customfile}"
                        )
                    )
                    functions.output_message(
                        f"Created {local_sshd_customfile}",
                        "s"
                    )

                local_sshd = os.path.dirname(local_sshd_customfile)
                sshd_config = os.path.dirname(SSHD_CONFIG[0])
                if local_sshd == sshd_config:
                    command = (
                        f"echo Include {local_sshd_customfile} "
                        f">> {SSHD_CONFIG[0]}"
                    )
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            f"Failed to include {local_sshd_customfile} "
                            f"in {SSHD_CONFIG[0]}"
                        )
                    )

                    functions.output_message(
                        (
                            f"included {local_sshd_customfile} in "
                            f"{SSHD_CONFIG[0]}"
                        ),
                        "s"
                    )

                for param, expected_value in params_to_add.items():
                    command = (
                        f"echo {param} {expected_value} >> "
                        f"{local_sshd_customfile}"
                    )
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            f"Failed to add paramter: {param} "
                            f"{expected_value} to {local_sshd_customfile}"
                        )
                    )
                    functions.output_message(
                        (
                            f"Added paramter: {param} {expected_value} "
                            f"to {local_sshd_customfile}"
                        ),
                        "s"
                    )

            if len(params_to_change) > 0:
                for param, values in params_to_change.items():
                    expected_value = values["expected_value"]
                    path_value = values["conf_file"]
                    param_found = False
                    command = f"cat {path_value}"
                    stdin, stdout, stderr = ssh.exec_command(command)
                    for line_number, line in enumerate(stdout, start=1):
                        if line.startswith(param):
                            param_found = True
                            if param in line:
                                command = (
                                    f"sed -i 's/^{param} .*/{param} "
                                    f"{expected_value}/' {path_value}"
                                )
                                functions.execute_ssh_command(
                                    ssh,
                                    command,
                                    (
                                        f"Failed to modify paramter: {param} "
                                        f"{expected_value} in {path_value}"
                                    )
                                )
                                functions.output_message(
                                    (
                                        f"Modified paramter: {param} "
                                        f"{expected_value} in {path_value}"
                                    ),
                                    "s"
                                )

        except Exception as e:
            functions.output_message(
                f"An error occurred: {e}",
                "e"
            )

        finally:
            if params_to_add or params_to_change:
                command = "systemctl restart ssh"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to restart SSH service"
                )
                functions.output_message(
                    "Restarted SSH service",
                    "s"
                )

        if iteration == 0:
            time.sleep(2)

    functions.output_message(
        "sshd_config is correct",
        "s"
    )


def set_pve_no_subscription(ssh, values):
    try:
        command = (
            'grep -q "^deb .*pve-no-subscription" '
            '/etc/apt/sources.list && echo "enabled"'
        )
        result = functions.execute_ssh_command(ssh, command)

        # Check the exit status directly
        if result == "enabled":
            functions.output_message(
                "pve-no-subscription repository is enabled.",
                "s"
            )
        else:
            # Try the next pattern if the first one wasn't found
            command = (
                'grep -q "^# deb .*pve-no-subscription" '
                '/etc/apt/sources.list && echo "commented"'
            )
            result = functions.execute_ssh_command(ssh, command)
            if result == "commented":
                functions.output_message(
                    (
                        "pve-no-subscription repository is found "
                        "but not enabled. Enabling it now..."
                    ),
                    "w"
                )
                # Step 2: Enable the pve-no-subscription
                # repository (uncomment it)
                command = (
                    "sed -i 's/^# deb \\(.*pve-no-subscription\\)/deb \\1/' "
                    "/etc/apt/sources.list"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "pve-no-subscription repository NOT enabled."
                )
                functions.output_message(
                    "pve-no-subscription repository has been enabled.",
                    "s"
                )
            else:
                functions.output_message(
                    (
                        "pve-no-subscription repository is not found "
                        "Adding it now..."
                    ),
                    "w"
                )
                # Step 3: Add the pve-no-subscription
                # repository to sources.list
                http_str = "deb http://download.proxmox.com/debian/pve "
                pve_no = "bookworm pve-no-subscription"
                command = (
                    'echo '
                    f'"{http_str} {pve_no}"'
                    ' | tee -a /etc/apt/sources.list > /dev/null'
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    (
                        "pve-no-subscription repository NOT added to "
                        "/etc/apt/sources.list."
                    )
                )
                functions.output_message(
                    (
                        "pve-no-subscription repository has been added to "
                        "/etc/apt/sources.list."
                    ),
                    "s"
                )

        # Step 4: Check and disable enterprise repository
        # if not already disabled
        command = (
            'grep -q "^deb .*bookworm pve-enterprise" '
            '/etc/apt/sources.list.d/pve-enterprise.list '
            '&& echo "enabled" || echo "disabled"'
        )
        enterprise_result = functions.execute_ssh_command(
            ssh,
            command
        )

        if enterprise_result == "enabled":
            functions.output_message(
                (
                    "Enterprise repository is enabled. Disabling it now "
                    "by commenting it out..."
                ),
                "w"
            )
            command = (
                r"sed -i 's/^\(deb .*bookworm pve-enterprise\)/# \1/' "
                r"/etc/apt/sources.list.d/pve-enterprise.list"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                "Enterprise repository NOT disabled."
            )
            functions.output_message(
                "Enterprise repository has been disabled.",
                "s"
            )
        else:
            functions.output_message(
                "Enterprise repository is disabled.",
                "s"
            )

        # Step 5: Comment out Ceph-related entries in ceph.list
        command = (
            'grep -q "^deb .*ceph-quincy bookworm enterprise" '
            '/etc/apt/sources.list.d/ceph.list && '
            'echo "enabled" || echo "disabled"'
        )
        ceph_list_result = functions.execute_ssh_command(
            ssh,
            command
        )

        if ceph_list_result == "enabled":
            functions.output_message(
                (
                    "ceph.list found. Commenting out ceph-quincy, "
                    "bookworm, or enterprise entries..."
                ),
                "w"
            )
            command = (
                r"sed -i 's/^\(deb .*bookworm enterprise\)/# \1/' "
                r"/etc/apt/sources.list.d/ceph.list")
            functions.execute_ssh_command(
                ssh,
                command,
                "Ceph-related entries NOT disabled."
            )
            functions.output_message(
                "Ceph-related entries has been disabled.",
                "s"
            )
        else:
            functions.output_message(
                "ceph.list is disabled.",
                "s"
            )

        # Step 6: Apply pve-no-subscription patch
        file_path = '/usr/share/perl5/PVE/API2/Subscription.pm'
        find_str = 'NotFound'
        replace_str = 'Active'

        # Check if the file exists
        command = (
            f'test -f "{file_path}" && echo "exists" || echo "not_exists"'
        )
        file_exists = functions.execute_ssh_command(
            ssh,
            command
        )

        if file_exists == "not_exists":
            functions.output_message(
                (
                    f"pve-no-subscription patch error: {file_path} "
                    "does not exist! Are you sure this is PVE?"
                ),
                "e"
            )
        else:
            # Check if the file contains 'NotFound'
            command = (
                f'grep -i "{find_str}" "{file_path}" && '
                'echo "found" || echo "not_found"'
            )
            find_result = functions.execute_ssh_command(
                ssh,
                command
            )

            if find_result == "not_found":
                functions.output_message(
                    "pve-no-subscription patch applied.",
                    "s"
                )
            else:
                # Apply the patch (replace 'NotFound' with 'Active')
                command = (
                    f'sed -i "s/{find_str}/{replace_str}/gi" "{file_path}"'
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "pve-no-subscription patch NOT applied."
                )
                functions.output_message(
                    f"Applied pve-no-subscription patch in {file_path}...",
                    "i"
                )

                # Restart the services
                functions.output_message(
                    "Restarting services...",
                    "i"
                )
                ssh.exec_command('systemctl restart pvedaemon')
                ssh.exec_command('systemctl restart pveproxy')

                functions.output_message(
                    f"Subscription updated from {find_str} to {replace_str}.",
                    "S"
                )

    except Exception as e:
        functions.output_message(
            f"Error with pve-no-subscription patch: {e}",
            "e"
        )


def download_iso(ssh, values):
    pve_iso_urls = values.get("pve_iso")  # Correct access to 'pve_iso' key
    try:
        if not pve_iso_urls:
            functions.output_message(
                "No ISO URLs provided in the configuration file.",
                "w"
            )
        else:
            # Step 1: Ensure the directory exists
            command = "mkdir -p /var/lib/vz/template/iso"
            functions.execute_ssh_command(
                ssh,
                command,
                "Unable to create var/lib/vz/template/iso on proxmox host."
            )
            functions.output_message(
                "Checkkng /var/lib/vz/template/iso exists on the remote host.",
                "s"
            )

            # Step 2: Check if each ISO image
            # already exists and download if not
            for url in pve_iso_urls:
                iso_filename = url.split('/')[-1]
                iso_filepath = f"/var/lib/vz/template/iso/{iso_filename}"

                # Check if the file already exists on the remote host
                command = (
                        f"test -f {iso_filepath} && "
                        "echo 'exists' || echo 'not_exists'"
                    )
                file_exists = functions.execute_ssh_command(
                    ssh,
                    command,
                    "Unable to get ISO file lsit."
                )

                if file_exists == "exists":
                    functions.output_message(
                        f"{iso_filename} already exists, skipping download.",
                        "s"
                    )
                else:
                    functions.output_message(
                        (
                             f"Downloading {iso_filename} to "
                             "/var/lib/vz/template/iso..."
                        ),
                        "i"
                    )

                    # Execute wget and wait for it to complete
                    download_cmd = f"wget -q -P /var/lib/vz/template/iso {url}"
                    stdin, stdout, stderr = ssh.exec_command(download_cmd)

                    # Wait for the command to complete and
                    # check if any errors occurred
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        functions.output_message(
                            f"{iso_filename} has been downloaded.",
                            "s"
                        )
                    else:
                        error_message = stderr.read().decode().strip()
                        functions.output_message(
                            (
                                f"Failed to download {iso_filename}. "
                                f"Error: {error_message}"
                             ),
                            "e"
                        )

    except Exception as e:
        functions.output_message(
            f"Error connecting to Proxmox host via SSH: {e}",
            "e"
        )


def change_remote_password(ssh, values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    pve_changepwd = values.get("pve_changepwd")

    if pve_changepwd is not False:
        try:
            new_password = getpass.getpass(
                f"Enter new password for '{pve_username}': "
            )
            if not new_password:
                functions.output_message(
                    "New password value is not set.",
                    "e"
                )
            # Command to change the password on the remote host
            change_password_cmd = (
                f'echo "{pve_username}:{new_password}" | chpasswd'
            )

            # Execute the command
            functions.output_message(
                f"Changing password on {pve_hostip}...",
                "i"
            )
            stdin, stdout, stderr = ssh.exec_command(change_password_cmd)

            # Wait for the command to finish and check for errors
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                functions.output_message(
                    (
                        f"Password for user {pve_username} on {pve_hostip} "
                        "has been updated."
                    ),
                    "s"
                )
            else:
                error_message = stderr.read().decode().strip()
                functions.output_message(
                    f"Failed to update password. Error: {error_message}",
                    "e"
                )

            # Close the SSH connection
            ssh.close()

        except Exception as e:
            functions.output_message(
                f"Error connecting to {pve_hostip}: {e}",
                "e"
            )


os.system('cls' if os.name == 'nt' else 'clear')
config_file = None
try:
    config_file = sys.argv[1]
except Exception as e:
    if config_file is None:
        functions.output_message()
        functions.output_message(
            f"Missig json-file arg: {e}",
            "e"
        )

script_directory = os.path.dirname(os.path.abspath(__file__))

functions.output_message()
functions.output_message("script info:", "h")
functions.output_message()
functions.output_message(f"Parameter filename: {config_file}")
functions.output_message(f"Script directory  : {script_directory}")
functions.output_message()

if config_file is not None:
    config = load_config(config_file)
else:
    functions.output_message(
        f"Unable to read: {config_file}",
        "e"
    )
values = get_json_values(config)

functions.output_message()
functions.output_message("Validate JSON structure", "h")
functions.output_message()
functions.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

functions.output_message()
functions.output_message("Validate JSON values", "h")
functions.output_message()
functions.check_values(config, integer_keys=INTEGER_KEYS)

functions.output_message()
functions.output_message("Configure PROXMOX host", "h")
functions.output_message()

# Establish SSH connection to Proxmox server
host = values.get("pve_host")
user = values.get("pve_user")
ssh = None
try:
    ssh = functions.ssh_connect(host, user, "", PVE_KEYFILE)
    if ssh is not None:
        add_snippets_folder(ssh, values)
        check_hostname(ssh, values)
        configure_sshd(ssh, values)
        set_pve_no_subscription(ssh, values)
        download_iso(ssh, values)
        change_remote_password(ssh, values)
        ssh.close()
        functions.output_message(f"Applied configuration: {config_file}", "s")
        functions.output_message()

except Exception as e:
    functions.output_message(
        f"SSH connection to PVE host failed: {e}",
        "e"
    )
    functions.output_message()
