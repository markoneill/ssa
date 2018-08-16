# Secure Socket API (SSA)
The SSA is a Linux kernel module that allows programmers create secure TLS connections using the standard POSIX socket API. This allows programmers to focus more on the developement of their apps without having to interface with complicated TLS libraries. The SSA also allows system administrtors and other power users to customize TLS settings for all connections on the machines they manage, according to their own needs.

## Publication
You can read more about the SSA, it's design goals, and features in our [USENIX Security 2018 paper](https://www.usenix.org/conference/usenixsecurity18/presentation/oneill)

## Prerequisites
The SSA has two components - a kernel module (this repository) and a [userspace daemon](https://github.com/markoneill/ssa-daemon).
Both need to be installed and running to provide TLS as an operating system service.
The userspace daemon has its own README with installation instructions.

Before building the SSA kernel module (this repo), you will need to install the relevant kernel headers and development packages for your Linux distribution

For example, on Fedora, run
```
sudo dnf install kernel-devel kernel-headers
```

## Build and Installation
To install the SSA module type these commands into the terminal while in the ssa project folder as root user
```
make
insmod ssa.ko
```

## Removal
To remove the SSA kernel module, shut down the encryption daemon (if running), and then the following command as a privileged user:
```
rmmod ssa
```

## Compatibility
The SSA is actively developed on Fedora, but may with with minor or few changes for other distributions.

## Status
The SSA is currently a research prototype. As such, it should not yet be used in any mission critical environments. However, we are working toward release as a viable tool for the general public.
