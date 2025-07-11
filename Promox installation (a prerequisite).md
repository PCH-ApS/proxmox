This guide aims to install Proxmox VE and configure the Proxmox host with a basic network setup, that can be customized further with scripts in this repository.

## Install Proxmox
- Boot on the Proxmox VE installation media and wait for the "**Welcome to Proxmox Virtual Environment**" screen.
  
  I would download the installation image ISO and write it to a USB drive using Etcher or a similar tool

### Proxmox installation steps
- Select Installation Option
  Choose Install Proxmox VE (Graphical).
- Accept the EULA
  Click the I agree button in the lower-right corner.
- Disk Selection
  Choose the target hard disk for installation.
	Click Options and:
		Set the filesystem to ZFS (RAID0). 
		This is what I select for my Proxmox VE servers, you should select what works for you.
	Click OK.
    Click Next in the lower-right corner.
- Location and Time Zone Settings
	Set the following:
		Country: Denmark
		Timezone: Europe/Copenhagen
		Keyboard Layout: Danish 
		Again, this is what I select for my Proxmox VE servers, you should select what works for you.
	Click Next.
- Administrative Settings
	Enter an administrative password.
		I use a simple password for this as I will change it later with code.
	Provide an admin email address.
	Click Next.
- Network Configuration
	Enter:
		FQDN: Any value (this will be updated by the script).
		IP Address: x.x.x.x/29 
		I have small network segments, and defaults to VLANs with /29-size.
		Gateway: y.y.y.y
		DNS Server: y.y.y.y
	Click Next.
- Start Installation
	Click the Install button in the lower-right corner.

Once the installation has been completed access the Proxmox web GUI on https://x.x.x.x:8006 to validate the installation if possible.

### Proxmox post installation steps
#### Set Proxmox host to DHCP (optional)
I segment my network, and each segment is usually a /29 subnet, and I have good control over which hosts are in what segment. 

I might run the installation while conneted to a test or config network or zone, that is not the intended final network for the host. When I move the Proxmox host into the desired network, I still want to be able to access it, and I set the host to DHCP. 

My configuration script will change it to a fixed ip, if specified in my config file for the host.

- Edit the network interfaces configuration file
```
nano /etc/network/interfaces
```
- Add the following:
```
iface vmbr0 inet dhcp
bridge-vlan-aware yes
bridge-vids 2-4094
```
- Comment out the following:
```
#iface vmbr0 inet static
#       address x.x.x.x/29
#       gateway y.y.y.y
```
- Save the changes and reboot the system.

#### Validate SSH access to Proxmox host
- Log in to the Proxmox host using SSH. 
  Change @x.x.x.x to the ip-address of the Proxmox host 
```
ssh -o IdentitiesOnly=yes root@x.x.x.x
```
- if successful, continue and copy your SSH key to the Proxmox root account.
  I assume that an SSH key has been created for use when logging into Proxmox as root. Replace ~/.ssh/Key-for-Proxmox.pub with the path for the key you want to use, and change @x.x.x.x to the ip-address of the Proxmox host 
```
ssh-copy-id -o IdentitiesOnly=yes -i ~/.ssh/Key-for-Proxmox.pub root@x.x.x.x
```
### Proxmox on a laptop
I use old laptops as test machines - also for Proxmox. It is a bit annoying that they can go into hibernation or sleep when the lid i closed, and therefor I add these twerks if I when I run Proxmox on a laptop.

- Access the host shell in the Proxmox web GUI or ssh to the host
- Modify logind.conf to prevent sleep when the lid is closed: 
```
nano /etc/systemd/logind.conf
```
- Modify the matching lines in the file to the below.
```
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
```
- Save changes and restart the service.
```
systemctl restart systemd-logind
```
- Reboot the system. 




