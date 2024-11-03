import sys
import os

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from const.vm_const import SSH_CONST, SSHD_CONFIG, SSHD_SEARCHSTRING, SSHD_CUSTOMFILE

ipaddress = "192.168.254.3"
ci_username = "pch"
ci_password = os.getenv("CI_PASSWORD")  # Retrieve the password from an environment variable

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

    #Er kommet her til !!!!


    # Check each parameter in every configuration file
    for param, expected_value in SSH_CONST.items():
        param_found = False  # Track if parameter was found in any file
        for conf_file in config_files:
            command = f"cat {conf_file}"
            stdin, stdout, stderr = ssh.exec_command(command)
            for line_number, line in enumerate(stdout, start=1):
                if line.startswith(param):
                    param_found = True
                    if expected_value in line:
                        params_no_change[param] = expected_value
                    else:
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

    print(f"Parameters that are correct: {params_no_change}")
    print(f"Parameters that must be changes: {params_to_change}")
    print(f"Parameters that must be added: {params_to_add}")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    ssh.close()
    print("SSH connection closed")
