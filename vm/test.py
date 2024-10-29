ipaddress = "192.168.254.3"
ci_username = "pch"
values = []

config_files = ["/etc/ssh/sshd_config"]
search_string = "Include "
conf_file_dir = []
elements = []

import sys
import os
# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions

ssh = functions.ssh_connect(ipaddress, ci_username)

try:
  # Step 1: Gather list of configuration files
  # Check if config_file has include statements to other *.conf files?
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

  for pattern in conf_file_dir:
    # Execute ls command to find all files matching the pattern
    command = f"ls {pattern} 2>/dev/null"
    stdin, stdout, stderr = ssh.exec_command(command)

    # Read the command output line by line and add to config_files
    matched_files = stdout.read().decode().splitlines()
    config_files.extend(matched_files)
    files_found = len(config_files)
    print(f"\033[93m[INFO]            : Found {files_found} sshd config files")

  # Step 2: Run thought all files found to check if parameters has been set
  params_to_check = {
    "PasswordAuthentication": "no",
    "ChallengeResponseAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "ClientAliveInterval": "3600",
    "ClientAliveCountMax": "2",
    "X11Forwarding": "no",
    "PermitRootLogin": "prohibit-password"
  }
  Params_to_set = {}

  for param, expected_value in params_to_check.items():
    for conf_file in config_files:
      command = f"cat {conf_file}"
      stdin, stdout, stderr = ssh.exec_command(command)
      for line_number, line in enumerate(stdout, start=1):
        if line.startswith(param):
            print(f"\033[93m[INFO]            : Found '{param}' in file '{conf_file}' at line {line_number}: {line.strip()}")
            if expected_value in line:
                print(f"\033[92m[OK]              : '{param}' is set to '{expected_value}' in file '{conf_file}'")
            else:
                print(f"\033[91m[WARNING]         : '{param}' is not set to '{expected_value}' in file '{conf_file}'")
                params_to_set[param] = expected_value

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    ssh.close()
    print("SSH connection closed")