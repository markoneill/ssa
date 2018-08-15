# Secure Socket API (SSA)
The SSA is a kernal module that allows programmers create a secure TLS connection using the POSIX API. This allows programmers to focus more on the developement of their apps without having to worry about security in their connections. The SSA also allows for sys admins to customize settings for their secure connections such as what cypher suites they want to use and what version of TLS they are willing to connect with.

## Prerequisites
If you have alread installed the ssa Daemon then all the packages that you need can be installed by using running `./install_packages.sh`

If you haven't run that script and just want the SSA you need to install kernal development tools 

```
sudo dnf install kernel-devel
```

## Installation
To install the SSA module type these commands into the terminal while in the ssa project folder as root user
```
make
insmod ssa.ko
```
## Configuration
The configuration features are in the ssa daemon c
## Compatibility
Currently the SSA works with Fedora 26 kernal v4.17
later versions of Fedora are supported with slight code changes
with changes slight changes Ubuntu should work as well
