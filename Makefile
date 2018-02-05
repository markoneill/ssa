ssa-objs := tls_upgrade.o tls_common.o tls_inet.o tls_unix.o netlink.o loader.o
obj-m += ssa.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
