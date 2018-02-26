#include <linux/net.h>
#include <linux/un.h>
#include <net/sock.h>
#include <linux/string.h>
#include <uapi/linux/uio.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/socket.h>
#include "tls_upgrade.h"
#include "tls_common.h"
#include "socktls.h"

#define TCP_UPGRADE_TLS	33

#define TLS_UPGRADE_NAME_MAX 18

#define MAX_CON_INFO_SIZE	64

int recv_con(struct socket* sock);
int sockdup2(int oldfd, struct socket* sock);
int getsk_fd(struct sock* sk);
ssize_t write_fd(int fd_gift, char* buf, int buf_sz, int port);

extern int (*orig_tcp_setsockopt)(struct sock*, int, int, char __user*, unsigned int);

// recieves a message back from the daemon as confirmation of file descriptor reciept
int recv_con(struct socket* sock) {
	char buf[1014];
	struct kvec iov;
	struct msghdr msg = {0};
	int err;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	err = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);

	if (err == -1) {
		printk(KERN_ERR "recvmsg error\n");
	} else {
		printk(KERN_INFO "Got msg(%d) \"%s\"\n", err, buf);
	}

	return err;
}

int sockdup2(int oldfd, struct socket* sock) {
	struct files_struct* files;
	struct file* filp;
	struct file* newfile;

	files = current->files;

	if (sock->file == NULL) {
		// create a file for the socket
		//TODO pass along nonblock as a flag if we are nonblocking
		newfile = sock_alloc_file(sock, 0, NULL);
		if (IS_ERR(newfile)) {
			printk(KERN_ERR "BAD NEWS BEARS couldn't give sock a file\n");
			return -1;
		}
	}

	// lock the files
	spin_lock(&files->file_lock);

	// grab the old filp
	filp = files->fdt->fd[oldfd];

	// NULL out oldfd
	files->fdt->fd[oldfd] = NULL;
	
	// replace it with the new
	fd_install(oldfd, sock->file); 

	// unlock
	spin_unlock(&files->file_lock);

	// close the old file
	filp_close(filp, files);

	return 0;
}

// finds the associated file descriptor for a struct sock*
int getsk_fd(struct sock* sk) {
	int i;
	struct fdtable* fdt;
	struct file* sk_fp;

	if (sk == NULL) {
		return -1;
	}

	sk_fp = sk->sk_socket->file;

	fdt = files_fdtable(current->files);

	for (i=0; i<fdt->max_fds; i++) {
		if (fdt->fd[i] == sk_fp) {
			return i;
		}
	}
	return -1;
}

// takes the fd you want to gift to the daemon
// the buf and buf size are the message
ssize_t write_fd(int fd_gift, char* buf, int buf_sz, int port) {
	int error;
	struct socket* sock;
	struct sockaddr_un addr;
	int addr_len;
    struct sockaddr_un self;
    char tls_upgrade_path[TLS_UPGRADE_NAME_MAX];
	int pathlen = snprintf(tls_upgrade_path, TLS_UPGRADE_NAME_MAX, "%ctls_upgrade%d", '\0', port);

	struct msghdr msg = {0};
	struct kvec iov;

	//TODO remove printfs from this call

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr* cmptr;

	error = sock_create(PF_UNIX, SOCK_DGRAM, 0, &sock); 
	if (error < 0) {
		printk(KERN_ERR "sock_create error\n");
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, tls_upgrade_path, pathlen);
	addr_len = pathlen + sizeof(sa_family_t);

	printk(KERN_INFO "Connecting to daemon\n");
	
	error = kernel_connect(sock, (struct sockaddr*)&addr, addr_len, 0);
	if (error < 0) {
		printk(KERN_ERR "connect error\n");
		sock_release(sock);
		return -1;
	}

	// make and send the message

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;

	*((int*) CMSG_DATA(cmptr)) = fd_gift;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = buf;
	iov.iov_len = buf_sz;

	iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, iov.iov_len);
	
	// before we send the message, we need to bind so they can send back something as a confirmation
	self.sun_family = AF_UNIX;
	
	printk(KERN_INFO "Binding for call back\n");

	// autobind only is invoked if bind size == 2 == sizeof(sa_family_t)
	if (kernel_bind(sock, (struct sockaddr*)&self, sizeof(sa_family_t)) == -1) {
		printk(KERN_ERR "bind error\n");
		sock_release(sock);
		return -1;
	}

	printk(KERN_INFO "gifting fd\n");
	error = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if (error == -1) {
		printk(KERN_ERR "sendmsg error\n");
	}

	// revc confirmation
	printk(KERN_INFO "recving confirmation\n");
	recv_con(sock);

	printk(KERN_INFO "got confirmation\n");

	// clean up
	sock_release(sock);
	return 0;
}

// hooks tcp's setsockopt so that we can find our special options
int hook_tcp_setsockopt(struct sock* sk, int level, int optname, char __user* optval, unsigned int optlen) {
	int fd;
	char con_info[MAX_CON_INFO_SIZE];
	int con_info_size;
	int is_accepting;
	int error;
	struct socket* new_sock;
	struct sockaddr_in daemon_addr;
	socket_state state;
	tls_sock_data_t* sock_data;// get_tls_sock_data(unsigned long key);
	
	//TODO get rid of printfs
	//printk(KERN_INFO "Hook called\n");
	// first check if it is our special opt
	// otherwise pass it on
	if (level == SOL_TCP && optname == TCP_UPGRADE_TLS) {
		if (optlen < sizeof(int)) {
			printk(KERN_ERR "optlen for TCP_UPGRADE_TLS was not\n");
			is_accepting = 0;
		} else {
			is_accepting = *((int*)optval);
		}
		
		printk(KERN_INFO "Got TCP_UPGRADE_TLS %d\n", is_accepting);
		// try to send some info to the server with a unix domain socket
		// find the fd associated with this sk
		fd = getsk_fd(sk);
		if (fd == -1) {
			printk(KERN_ERR "BadBadNotGood Couldn't find sk in fd\n");
			return -1;
		}
		
		printk(KERN_INFO "Making replacement connection\n");
		// make tls sock
		error = sock_create_kern(current->nsproxy->net_ns, PF_INET, SOCK_STREAM, IPPROTO_TLS, &new_sock);
		if (error != 0) {
			printk(KERN_ERR "Could not create TLS socket :(\n");
			return -1;
		}
		printk(KERN_INFO "Made replacement connection\n");

		sock_data = get_tls_sock_data((unsigned long)new_sock);
		
		// on this tcp sock we need to know if this is a connection, unconnected, listening, accepted
		// check if it is already connected, if so connect it
		state = sk->sk_socket->state;
		
		// create the correct message to send
		con_info_size = snprintf(con_info, MAX_CON_INFO_SIZE, "%d:%lu", is_accepting, (long unsigned int)(void*)new_sock);
		// gift the original connection
		// and recv for a completion
		error = write_fd(fd, con_info, con_info_size, sock_data->daemon_id);
		if (error < 0) {
			printk(KERN_ERR "Error sending the file descriptor to the daemon\n");
			sock_release(new_sock);
			return -1;
		}
		printk(KERN_INFO "Sent fd\n");

		if (is_accepting || state == SS_CONNECTED || state == SS_CONNECTING) {
			// connect the socket
			// to localhost 8443
			// if we direct connect it is cool
			daemon_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			daemon_addr.sin_family = AF_INET;
			daemon_addr.sin_port = htons(sock_data->daemon_id);
		
			printk(KERN_INFO "Connecting replacement connection\n");
			error = kernel_connect(new_sock, (struct sockaddr*)&daemon_addr, sizeof(daemon_addr), 0);
			if (error < 0) {
				printk(KERN_ERR "Error connecting to the daemon for the replacement connection\n");
				sock_release(new_sock);
				return -1;
			}
		}
		
		// dup2 tls over fd
		// so we can't acutally use dup_2, so we null out the fd and install it quickly, haha.
		sockdup2(fd, new_sock);
		
		return 0;
	}	

	return orig_tcp_setsockopt(sk, level, optname, optval, optlen);
}
