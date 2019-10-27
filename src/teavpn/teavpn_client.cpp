
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn/teavpn.h>
#include <teavpn/helpers.h>
#include <teavpn/teavpn_client.h>
#include <teavpn/teavpn_config_parser.h>

#define BUFSIZE 2000

extern uint8_t verbose_level;

static bool teaclient_init_iface(int net_fd, client_config *config);

static ssize_t cread(int fd, char *buf, int n) {
	ssize_t nread;
	if ((nread = read(fd, buf, n)) < 0) {
	}
	return nread;
}
static ssize_t cwrite(int fd, char *buf, int n) {
	ssize_t nwrite;

	if ((nwrite = write(fd, buf, n)) < 0){
	}
	return nwrite;
}
static ssize_t read_n(int fd, char *buf, int n) {
	ssize_t nread, left = n;
	while (left > 0) {
		if ((nread = cread(fd, buf, left)) == 0) {
			return 0;
		} else {
			left -= nread;
			buf += nread;
		}
	}
	return n;  
}

/**
 * @param client_config *config
 * @return uint8_t
 */
uint8_t teavpn_client(client_config *config)
{
	char buffer[BUFSIZE];
	struct sockaddr_in remote;
	int net_fd, tap_fd, maxfd;
	uint64_t tap2net = 0, net2tap = 0;
	ssize_t nread, nwrite, plength;

	verbose_level = config->verbose_level;

	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(config->server_ip);
	remote.sin_port = htons(config->server_port);

	// Create TUN/TAP interface.
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully connected to interface \"%s\".\n", config->dev);

	// Create socket.
	debug_log(2, "Initializing socket...");
	if ((net_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
		perror("socket()");
		return 1;
	}
	debug_log(2, "OK\n");

	// Setting socket.
	debug_log(2, "Setting up socket options...");
	debug_log(2, "OK\n");

	// Connect to server.
	debug_log(1, "Connecting to %s:%d...\n", config->server_ip, config->server_port);
	if (connect(net_fd, (struct sockaddr*)&remote, sizeof(remote)) < 0){
		perror("connect()");
		return 1;
	}
	debug_log(1, "Connection established\n");

	teaclient_init_iface(net_fd, config);

	debug_log(2, "CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

	maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

	while (1) {
		int ret;
		fd_set rd_set;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(net_fd, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR){
			continue;
		}

		if (ret < 0) {
			perror("select()");
			exit(1);
		}

		if (FD_ISSET(tap_fd, &rd_set)){
			// data from tun/tap: just read it and write it to the network

			nread = cread(tap_fd, buffer, BUFSIZE);

			tap2net++;
			debug_log(3, "TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

			/* write length + packet */
			plength = htons(nread);
			nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
			nwrite = cwrite(net_fd, buffer, nread);

			debug_log(3, "TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
		}

		if (FD_ISSET(net_fd, &rd_set)) {
			/* data from the network: read it, and write it to the tun/tap interface. 
			* We need to read the length first, and then the packet */

			// Read length
			nread = read_n(net_fd, (char *)&plength, sizeof(plength));

			if (nread == 0) {
				// ctrl-c at the other end
				break;
			}

			net2tap++;

			// read packet
			nread = read_n(net_fd, buffer, ntohs(plength));
			debug_log(3, "NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

			// now buffer[] contains a full packet or frame, write it into the tun/tap interface
			nwrite = cwrite(tap_fd, buffer, nread);
			debug_log(3, "NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
		}
	}

	return 0;
}

/**
 * @param client_config *config
 * @return uint8_t
 */
static bool teaclient_init_iface(int net_fd, client_config *config)
{
	
	return true;
}
