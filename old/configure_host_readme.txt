Proxmox Host Configuration Script

This script automates the configuration of a Proxmox Virtual Environment (PVE) host using SSH. It performs tasks such as updating the hostname, configuring SSH daemon settings, enabling the no-subscription repository, downloading ISO images, and changing the remote user's password. The script reads settings from a JSON configuration file provided as a command-line argument.
Features

    Validates the JSON configuration file for required keys and values.
    Connects to the Proxmox host via SSH.
    Ensures that the 'snippets' folder exists and is properly configured.
    Checks and updates the Proxmox host's hostname.
    Configures SSH daemon settings according to specified parameters.
    Sets up the Proxmox VE no-subscription repository and applies necessary patches.
    Downloads specified ISO images to the Proxmox host.
    Changes the password of the remote user if required.

Requirements

    Python 3.x
    Paramiko library (pip install paramiko)
    Custom Modules:
        lib.functions: Contains utility functions used in the script.
        const.host_const: Contains constants used in the script.
    SSH access to the Proxmox host with necessary permissions.
    A JSON configuration file with the required settings.