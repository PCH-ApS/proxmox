**Welcome to My Proxmox Automation Repo!**
The purpose of this repository is to automate Proxmox tasks.
## Preface
I want to move out of the cloud services that I have used for the last many years, and I have decided to build up my own infrastructure again - to support my business. 

I tend to forget how I do tasks I don´t do very often, and therefor I have decided that this time I will try and automate as much as I can and build it as infrastructure as code to the extent i am capable of. 

Much can probably be automated much more clever (and better) then what I am doing in this repo. This is what I have come up with - and I have used AI chatbots along the way.
I haven´t been in a developer role for almost 20 years, and there is lots I have to relearn. I have a pretty clear vision of what I want to achieve and I have used AI to help me get there.

## The idea
My idea is to be able to spin up my infrastructure fast with code. Both to be able to handle the initial spin up, and when something goes horribly wrong and I have to recreate everything. Then next thing I want is to make it in a way that I can use the code to check the active configuration - making sure the environment is consistent with what I want. 

This repository shall enable me to:
- deploy a Proxmox host, configure it, and make it ready for (Linux) servers to be deployed on to the host.
- deploy server on the host

All should be done with IaC and config files for the host and the servers

## The goal
Eventually I hope to get to a point where I can have one or more pipelines running, creating and maintaining servers on the host, depending on the config files provided. I would like to come to a oint where I can just create a new config file, upload it to the repo and then wait a few minutes for the server to be available.

### Proxmox
I had a look at bootstapping Promox. I decided that the effort needed to get it to work, was not worth it, compared to a next, next, next installation of Proxmox that I then clould modify with code and config files.

Please read the [Promox installation (a prerequisite)](https://github.com/PCH-ApS/proxmox/blob/main/Promox%20installation%20(a%20prerequisite).md) to prepare the Proxmox host
