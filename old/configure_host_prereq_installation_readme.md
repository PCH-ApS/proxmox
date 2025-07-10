Install Proxmox on Host
Boot from Proxmox Installation Media

    Use a Proxmox VE ISO image written to a USB drive.
    Boot the system and wait for the "Welcome to Proxmox Virtual Environment" screen.

Proxmox Installation Steps

        Select Installation Option
            Choose Install Proxmox VE (Graphical).

        Accept the EULA
            Click the I agree button in the lower-right corner.

        Disk Selection
            Choose the target hard disk for installation.
            Click Options and:
                Set the filesystem to ZFS (RAID0). This is what I select for my Proxmox VE servers, you should select with works for you.
                Click OK.
            Click Next in the lower-right corner.

        Location and Time Zone Settings
            Set the following:
                Country: Denmark
                Timezone: Europe/Copenhagen
                Keyboard Layout: Danish Again, this is what I select for my Proxmox VE servers, you should select with works for you.
            Click Next.

        Administrative Settings
            Enter an administrative password (this will be changed later).
            Provide an admin email address.
            Click Next.

        Network Configuration
            Enter:
                FQDN: Any value (this will be updated by the script).
                IP Address: x.x.x.x/29 I have small network segments, and defaults to VLANs with /29-size.
                Gateway: y.y.y.y
                DNS Server: y.y.y.y
            Click Next.

        Start Installation
            Click the Install button in the lower-right corner.

Post-Installation Steps
If Running Proxmox on a Laptop:

    Access the shell via the Proxmox web GUI.

    Modify logind.conf to prevent sleep when the lid is closed: nano /etc/systemd/logind.conf

        Uncomment and change the following lines:

        HandleLidSwitch=ignore

        HandleLidSwitchExternalPower=ignore

        HandleLidSwitchDocked=ignore

        Save changes and restart the service:

        systemctl restart systemd-logind

    Reboot the system.

Validate SSH Access

    Log in via SSH:

    ssh -o IdentitiesOnly=yes root@x.x.x.x

    Copy your SSH key to the Proxmox root account: I assume that an SSH key has been created for use when logging into Proxmox as root. Replace ~/.ssh/Key-for-Proxmox.pub with the path for the key you want to use.

    ssh-copy-id -o IdentitiesOnly=yes -i ~/.ssh/Key-for-Proxmox.pub root@x.x.x.x

Configure DHCP for the Host

    Edit the network interfaces configuration file:

    nano /etc/network/interfaces

    Update the following:

        Add:

        iface vmbr0 inet dhcp

        bridge-vlan-aware yes

        bridge-vids 2-4094

        Comment out or remove:

        #iface vmbr0 inet static

        #       address x.x.x.x/29

        #       gateway y.y.y.y

    Save the changes and reboot the system.

This guide ensures that Proxmox is installed and configured with a basic network setup. For further customizations and automation, check out the scripts and configuration files in this repository.
