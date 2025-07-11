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

Once the installation has been completed access the Proxmox web GUI on https://x.x.x.x:8006

### Proxmox post installation steps
#### Proxmox on a laptop
I use old laptops as test machines - also for Proxmox. It is a bit annoying that they can go into hibernation or sleep when the lid i closed, and therefor I add these twerks if I when I run Proxmox on a laptop.

- Access the host shell in the Proxmox web GUI or ssh to the host
- Modify logind.conf to prevent sleep when the lid is closed: 
  ```nano /etc/systemd/logind.conf```
- 
