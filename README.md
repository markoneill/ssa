# Secure Socket API (SSA)
The SSA is a system that allows programmers to easily create secure TLS connections using the standard POSIX socket API. This allows programmers to focus more on the developement of their apps without having to interface with complicated TLS libraries. The SSA also allows system administrtors and other power users to customize TLS settings for all connections on the machines they manage, according to their own needs.

## How it Works
The SSA has two components: a kernel module and a userspace daemon. The kernel module intercepts system calls for TLS-configured sockets and redirects them to the daemon, which does the heavy lifting of establishing a secure TLS connection.

When SSA is installed, application developers can configure POSIX sockets for TLS by using the `IPPROTOTLS` flag in the call to `socket`. They can then use the sockets with the regular socket system calls.

TLS settings are configured by the system administrator using a config file. SSA shifts the burden of choosing configurations from the application developer to the system administrator running the application. This makes the development process much simpler,and gives the adminstrator control over the security settings for applications running on the system.

## Publication
You can read more about the SSA, it's design goals, and features in our [USENIX Security 2018 paper](https://www.usenix.org/conference/usenixsecurity18/presentation/oneill)

## Our Vision
The SSA was created by Mark O'Neill for his Ph.D. dissertation, in which he demonstrated a need for an easier way to write secure software. He created the SSA as a prototype solution to meet that need. We are currently working to make this project fully-functional so that it can be adopted in real-world applications. We look forward to collaboration with the open-source community to make this vision a reality.

## Status
The SSA is still undergoing large changes as we finalize certificate validation strategies and improve error reporting. As such, it should not yet be used in any mission critical environments. However, we are working toward release as a viable tool for the general public.

## Guide to this repository
The SSA is split into two repositories. This repository contains the source code for the kernel module. The [other repo](https://github.com/markoneill/ssa-daemon) contains the source code for the userspace daemon, as well as all documentation for the SSA. To learn more about the SSA, check out the `README.md` and `docs` directory of the other repository. 

## Contributions and Thanks
Thank you to Eliezer Colon for noting a compilation issue
