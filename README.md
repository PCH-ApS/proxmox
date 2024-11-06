# proxmox
This repository contains a set of Python scripts designed to automate various aspects of managing and configuring Proxmox environments. The scripts cover the following core functionalities:

Proxmox Setup Configuration: Automates initial configuration of a Proxmox server, including SSH setup, hostname configuration, Proxmox subscription handling, and ISO downloads.

Proxmox Template Creation: Creates server templates for reuse, ensuring consistency in the virtual environments by configuring key components such as CPU, memory, storage, network, and cloud-init settings.

Proxmox Virtual Machine Creation: Clones virtual machines from predefined templates, configures settings such as networking, cloud-init customization, and boot settings, and ultimately prepares the VM for deployment.

Why Use These Scripts?

Managing a Proxmox environment often involves repetitive tasks, particularly when setting up new hosts or virtual machines. These scripts aim to streamline the setup and management process, making it more efficient and less error-prone. By providing a consistent, automated approach, these scripts help ensure that Proxmox resources are configured reliably and quickly.

Combined Features

Automates the configuration of Proxmox hosts and virtual machines.

Supports end-to-end setup from host configuration, template creation, to VM deployment.

Uses cloud-init for initializing virtual machines, enabling customization during the provisioning phase.

Performs error checking and validation to ensure the reliability of configurations.

Prerequisites

All scripts are written in Python 3 and require the installation of necessary libraries such as Paramiko for SSH communication. Each script uses a configuration file in JSON format to provide specific details about the desired settings.

Make sure to:

Install Python 3 on your system.

Install dependencies using pip:

pip install paramiko

Provide a properly structured JSON configuration file with the required fields, as described in each script's individual documentation.

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

# Proxmox Template Creation Script

This repository contains a Python script designed to automate the creation of server templates on a Proxmox host. The script performs various tasks including validating configurations, checking resource availability, and configuring the template to specific requirements.

## Features
- Validates a configuration file in JSON format.
- Establishes SSH connection with Proxmox server using Paramiko.
- Checks if the desired template ID is already in use.
- Verifies if the required network bridge and local storage exist.
- Creates a new virtual machine template on the Proxmox server.

## Prerequisites
- **Python 3**: Ensure Python 3 is installed on your system.
- **Dependencies**: Install required Python libraries using pip:
  
  ```sh
  pip install paramiko
  ```
- **JSON Configuration**: Provide a configuration file in JSON format with the following fields
  See the create_template_master.json in the template folder

## Usage
1. Clone this repository:

   ```sh
   git clone https://github.com/yourusername/proxmox-template-script.git
   cd proxmox-template-script
   ```

2. Update the configuration file:

   Create a JSON configuration file that includes the necessary Proxmox details (refer to the structure mentioned above).

3. Run the script:

   ```sh
   ./proxmox_template.py <config_file_path>
   ```
   Replace `<config_file_path>` with the path to your JSON configuration file.

## Key Functions
- **`load_config(config_file)`**: Loads and validates the JSON configuration file.
- **`get_json_values(config)`**: Extracts key values from the JSON file for further processing.
- **`check_template_id_in_use(ssh, values)`**: Checks if the specified template ID is already in use on the Proxmox host.
- **`check_bridge_exists(ssh, values)`**: Verifies if the specified network bridge exists and is active.
- **`check_storage_exists(ssh, values)`**: Confirms if the specified storage location exists on the Proxmox host.
- **`create_template(ssh, values)`**: Creates the server template on the Proxmox host using the specified parameters.

## Example
To execute the script:

```sh
./proxmox_template.py config.json
```

This will run all the necessary validation checks and create the Proxmox template as specified in the `config.json` file.

## Error Handling
The script uses a variety of checks to ensure successful template creation, including:
- JSON validation checks.
- Verification of template ID, bridge, and storage availability.
- Handling of missing or incorrectly configured fields.

If an error occurs, the script prints a detailed error message and stops further execution.

## Important Notes
- **SSH Keys**: Ensure that you have appropriate SSH access to the Proxmox host.
- **Run as Root**: Some commands in this script (e.g., creating templates, modifying system files) require elevated privileges.


# Proxmox Virtual Machine Creation Script

This repository contains a Python script designed to automate the creation of virtual machines on a Proxmox host. The script performs various tasks including validating configurations, checking resource availability, and configuring the VM based on specific requirements.

## Features
- Validates a configuration file in JSON format.
- Establishes SSH connection with Proxmox server using Paramiko.
- Checks if the desired VM ID is already in use.
- Verifies if the required network bridge and local storage exist.
- Clones a template and configures a new virtual machine on the Proxmox server.
- Sets up cloud-init for custom initialization of the VM.

## Prerequisites
- **Python 3**: Ensure Python 3 is installed on your system.
- **Dependencies**: Install required Python libraries using pip:
  
  ```sh
  pip install paramiko
  ```
- **JSON Configuration**: Provide a configuration file in JSON format with the following fields:
See the create_vm_master.json in the vm folder

## Usage
1. Clone this repository:

   ```sh
   git clone https://github.com/yourusername/proxmox-vm-script.git
   cd proxmox-vm-script
   ```

2. Update the configuration file:

   Create a JSON configuration file that includes the necessary Proxmox details (refer to the structure mentioned above).

3. Run the script:

   ```sh
   ./proxmox_vm.py <config_file_path>
   ```
   Replace `<config_file_path>` with the path to your JSON configuration file.

## Key Functions
- **`load_config(config_file)`**: Loads and validates the JSON configuration file.
- **`get_json_values(config)`**: Extracts key values from the JSON file for further processing.
- **`check_conditional_values(values)`**: Validates certain optional fields, providing defaults when necessary.
- **`create_server(ssh, values)`**: Clones the template and creates the new VM with specified parameters.
- **`create_ci_options(ssh, values)`**: Configures cloud-init settings for the newly created VM.
- **`create_cloudinit(ssh, values)`**: Creates a custom cloud-init YAML file on the Proxmox host.
- **`start_vm(ssh, values)`**: Starts the newly created VM.
- **`get_vm_ipv4_address(ssh, values)`**: Waits for and retrieves the VM's IPv4 address.
- **`temp_fix_cloudinit(ssh, values)`**: Applies temporary fixes to cloud-init settings if needed.

## Example
To execute the script:

```sh
./proxmox_vm.py config.json
```

This will run all the necessary validation checks, clone the VM from the specified template, and configure the Proxmox virtual machine as specified in the `config.json` file.

## Error Handling
The script uses a variety of checks to ensure successful VM creation, including:
- JSON validation checks.
- Verification of template ID, bridge, and storage availability.
- Handling of missing or incorrectly configured fields.

If an error occurs, the script prints a detailed error message and stops further execution.

## Important Notes
- **SSH Keys**: Ensure that you have appropriate SSH access to the Proxmox host.
- **Run as Root**: Some commands in this script (e.g., cloning templates, modifying system files) require elevated privileges.

## Acknowledgments
Special thanks to all contributors and the open-source community for providing useful tools and libraries.
