# proxmox
repo for proxmox automation

### Proxmox Configuration Automation Script

This repository contains a Python script designed to automate the configuration of a Proxmox server. The script facilitates various tasks, including setting up SSH access, hostname configuration, Proxmox subscription handling, and ISO downloads.

## Features
- Validates a configuration file in JSON format.
- Establishes SSH connection with Proxmox server using Paramiko.
- Creates snippets folder on Proxmox server.
- Validates and updates the server's hostname.
- Configures `sshd_config` settings.
- Sets the Proxmox server to use the "no subscription" repository.
- Downloads required ISO files to the Proxmox server.
- Allows remote password changes for a specific user.

## Prerequisites
- **Python 3**: Ensure Python 3 is installed on your system.
- **Dependencies**: Install required Python libraries using pip:
  
  ```sh
  pip install paramiko
  ```
- **JSON Configuration**: Provide a configuration file in JSON format with the following fields:
  
See the configure_host.json in the proxmomx-host folder

## Usage
1. Clone this repository:

   ```sh
   git clone https://github.com/yourusername/proxmox-config-script.git
   cd proxmox-config-script
   ```

2. Update the configuration file:

   Create a JSON configuration file that includes the necessary Proxmox details (refer to the structure mentioned above).

3. Run the script:

   ```sh
   ./proxmox_config.py <config_file_path>
   ```
   Replace `<config_file_path>` with the path to your JSON configuration file.

## Key Functions
- **`load_config(config_file)`**: Loads and validates the JSON configuration file.
- **`get_json_values(config)`**: Extracts key values from the JSON file for further processing.
- **`check_hostname(ssh, values)`**: Checks the current hostname and changes it if necessary.
- **`configure_sshd(ssh, values)`**: Configures `sshd_config` based on provided settings.
- **`set_pve_no_subscription(ssh, values)`**: Configures Proxmox to use the community "no subscription" repository.
- **`download_iso(ssh, values)`**: Downloads ISO files to Proxmox for use.
- **`change_remote_password(ssh, values)`**: Changes the password for a specified user on the Proxmox server.

## Example
To execute the script:

```sh
./proxmox_config.py config.json
```

This will run all the configuration steps described above, using the parameters specified in the `config.json` file.

## Error Handling
The script uses a variety of checks to ensure successful configuration, including:
- JSON validation checks.
- Retry logic for SSH connections after hostname changes.
- Handling of missing or incorrectly configured fields.

If an error occurs, the script prints a detailed error message and stops further execution.

## Important Notes
- **SSH Keys**: Ensure the public SSH key provided in the JSON configuration is valid and can be used to connect to the Proxmox host.
- **Run as Root**: Some commands in this script (e.g., creating directories, modifying system files) require elevated privileges.

## Acknowledgments
Special thanks to all contributors and the open-source community for providing useful tools and libraries.
