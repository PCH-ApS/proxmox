import sys
import os

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions

ipaddress = "192.168.254.3"
ci_username = "pch"
#ci_password = "password"
ci_password = os.getenv("CI_PASSWORD")  # Retrieve the password from an environment variable


config_files = ["/etc/ssh/sshd_config"]
search_string = "Include "
conf_file_dir = []
config_filename = "/99-automation-default-config"
config_include = False


if not ci_password:
    raise EnvironmentError("The environment variable 'CI_PASSWORD' is not set. Please set it before running the script.")

# Connect to the SSH server
ssh = functions.ssh_connect(ipaddress, ci_username)

try:
    # Command to append text to the configuration file
    #command = f"sudo -S -i bash -c 'echo \"test\" >> /etc/ssh/sshd_config.d/test.conf'"
    command = f"echo {ci_password} | sudo -S -p '' bash -c 'echo \"test\" >> /etc/ssh/sshd_config.d/test.conf'"
    stdin, stdout, stderr = ssh.exec_command(command)
    stdin.write(f"{ci_password}\n")
    stdin.flush()

    # Check output and errors
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')

    if error:
        print(f"Command failed with error: {error}")
    else:
        print("Command executed successfully")
        print(output)

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    ssh.close()
    print("SSH connection closed")