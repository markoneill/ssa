tor_router-objs := tor_route_module.o tls_prot_tor.o 
obj-m += tor_router.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o autotor_loader autotor_loader.c

.PHONY : clean
clean :
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rm autotor_loader
