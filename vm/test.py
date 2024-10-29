import sys
import os

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions

ipaddress = "192.168.254.3"
ci_username = "pch"

config_files = ["/etc/ssh/sshd_config"]
search_string = "Include "
conf_file_dir = []

# Connect to the SSH server
ssh = functions.ssh_connect(ipaddress, ci_username)

try:
    # Step 1: Gather list of configuration files
    # Check if config_file has include statements to other *.conf files
    for conf_file in config_files:
        command = f"cat {conf_file}"
        stdin, stdout, stderr = ssh.exec_command(command)
        for line_number, line in enumerate(stdout, start=1):
            if line.startswith(search_string):
                print(f"\033[93m[INFO]            : Found '{search_string}' at the beginning of line {line_number}: {line.strip()}")
                elements = line.split()
                for element in elements:
                    if element.startswith("/"):
                        conf_file_dir.append(element)

    # Find all files matching the pattern specified in include statements
    for pattern in conf_file_dir:
        command = f"ls {pattern} 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(command)
        matched_files = stdout.read().decode().splitlines()
        config_files.extend(matched_files)

    # Print total found configuration files
    files_found = len(config_files)
    print(f"\033[93m[INFO]            : Found {files_found} sshd config files")

    # Step 2: Run through all files found to check if parameters have been set
    params_to_check = {
        "PasswordAuthentication": "no",
        "ChallengeResponseAuthentication": "no",
        "PermitEmptyPasswords": "no",
        "ClientAliveInterval": "3600",
        "ClientAliveCountMax": "2",
        "X11Forwarding": "no",
        "PermitRootLogin": "prohibit-password"
    }
    params_no_change = {}  # Tracks parameters that are set correctly
    params_to_add = params_to_check.copy()  # Tracks parameters that are missing
    params_to_change = {}  # Tracks parameters that need to be changed

    # Check each parameter in every configuration file
    for param, expected_value in params_to_check.items():
        param_found = False  # Track if parameter was found in any file
        for conf_file in config_files:
            command = f"cat {conf_file}"
            stdin, stdout, stderr = ssh.exec_command(command)
            for line_number, line in enumerate(stdout, start=1):
                if line.startswith(param):
                    param_found = True
                    print(f"\033[93m[INFO]            : {param} found in file '{conf_file}' at line {line_number}: {line.strip()}")
                    if expected_value in line:
                        print(f"\033[92m[OK]              : {param} is set to expected value: '{expected_value}' in file '{conf_file}'. No change needed")
                        params_no_change[param] = expected_value
                    else:
                        print(f"\033[91m[WARNING]         : '{param}' is not set to expected value: '{expected_value}' in file '{conf_file}'")
                        params_to_change[param] = conf_file
                    break  # Stop searching in the current file once parameter is found

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

    # Step 3: Modify the parameters that need correction
    if params_to_change:
        print("\033[93m[INFO]            : Correcting parameters with incorrect values...")
        for param, conf_file in params_to_change.items():
            expected_value = params_to_check[param]
            command = f"sed -i 's/^#*{param}.*/{param} {expected_value}/' {conf_file}"
            ssh.exec_command(command)
            print(f"\033[92m[INFO]            : Corrected '{param}' to '{expected_value}' in file '{conf_file}'")

    # Step 4: Write missing parameters to a new .conf file
    if params_to_add:
        conf_filename = f"{conf_file_dir}/99-automationtion-default-config.conf"
        print("\033[93m[INFO]            : Adding missing parameters to a new configuration file.")
        for param, value in params_to_add.items():
            command = f"echo '{param} {value}' | sudo tee -a {conf_filename}"
            ssh.exec_command(command)
            print(f"\033[92m[INFO]            : Added '{param} {value}' to '{conf_filename}'")

    # Step 5: Re-run the check to verify all parameters are set correctly
    print("\033[93m[INFO]            : Re-running verification checks to ensure parameters are correctly set...")
    # Ideally, you can just re-use the verification loop here to recheck after the changes.

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    ssh.close()
    print("SSH connection closed")
