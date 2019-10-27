
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
#include <teavpn/teavpn_server.h>
#include <teavpn/teavpn_config_parser.h>

#define BUFSIZE 2000

extern char **argv;
extern uint8_t verbose_level;

static uint8_t thread_amount;
static int *master_tap_fd;
static int *master_sock_fd;
static int *master_net_fd;
static bool *master_thread_busy;

static void *teavpn_thread_worker(void *arg);
static void teavpn_worker(int net_fd, int tap_fd);
static void teaserver_init_iface(server_config *dev);
static bool teavpn_server_socket_setup(int sock_fd);

uint8_t teavpn_server(server_config *config)
{
	// client_state *in;
	int tap_fd, sock_fd, net_fd;
	socklen_t remote_len;
	uint8_t thread_pos = 0;
	struct sockaddr_in local;

	master_tap_fd = &tap_fd;
	master_sock_fd = &sock_fd;

	if (config->config_file != NULL) {
		char config_buffer[4096];
		if (!teavpn_server_config_parser(config_buffer, config)) {
			return 1;
		}
	}

	verbose_level = config->verbose_level;

	// Check wheter dev name has valid size.
	if (strlen(config->dev) >= IFNAMSIZ) {
		printf("Dev name is too long.\nProvided dev name: \"%s\"\n", config->dev);
		return 1;
	}


	// Check wheter mtu value is valid.
	if (config->mtu <= 0) {
		printf("Invalid mtu value\n");
		return 1;
	}

	thread_amount = config->threads;

	// Declare pthread_t
	pthread_t teavpn_threads[thread_amount];
	bool thread_busy[thread_amount];
	master_thread_busy = thread_busy;

	for (uint8_t i = 0; i < config->threads; i++) {
		thread_busy[i] = false;
	}

	// Create TUN/TAP interface.
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully connected to interface \"%s\".\n", config->dev);

	teaserver_init_iface(config);

	// Create socket.
	debug_log(2, "Initializing socket...");
	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		return 1;
	}
	debug_log(2, "OK\n");

	// Setting socket.
	debug_log(2, "Setting up socket options...");
	teavpn_server_socket_setup(sock_fd);
	debug_log(2, "OK\n");


	// Prepare socket bind.
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(config->bind_port);
	local.sin_addr.s_addr = inet_addr(config->bind_addr);


	// Bind socket.
	if (bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
		perror("bind()");
		return 1;
	}


	// Listen socket.
	if (listen(sock_fd, 5) < 0) {
		perror("listen()");
		return 1;
	}

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// // Initialize threads
	// for (uint8_t i = 0; i < config->threads; i++) {
	// 	uint8_t *m = (uint8_t *)malloc(sizeof(uint8_t));
	// 	*m = i;
	// 	pthread_create(&(teavpn_threads[i]), NULL, teavpn_thread_worker, (void *)m);
	// }

	// Accept connection.
	remote_len = sizeof(struct sockaddr_in);

	while (1) {

		struct sockaddr_in addr;

		net_fd = accept(sock_fd, (struct sockaddr *)&addr, &remote_len);
		thread_busy[thread_pos] = true;
		thread_pos++;

		if (!fork()) {
			char buf[100];
			strcpy(buf, argv[0]);
			sprintf(argv[0], "%s:serving %s:%d", buf, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			teavpn_worker(net_fd, tap_fd);
			exit(0);
		}

		// if (thread_pos == thread_amount) {
		// 	while (1) sleep(1000000);
		// }
	}
}

static ssize_t cread(int fd, char *buf, int n)
{
	ssize_t nread;

	if ((nread = read(fd, buf, n)) < 0) {
		perror("read");
	}
	return nread;
}

static ssize_t cwrite(int fd, char *buf, int n)
{
	ssize_t nwrite;

	if ((nwrite = write(fd, buf, n)) < 0){
		perror("write");
	}
	return nwrite;
}

static ssize_t read_n(int fd, char *buf, int n)
{
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
 * @param int net_fd
 * @param int tap_fd
 * @return void
 */
static void teavpn_worker(int net_fd, int tap_fd)
{
	fd_set rd_set;
	char buffer[BUFSIZE];
	ssize_t nread, nwrite, plength;
	uint64_t tap2net = 0, net2tap = 0;
	int ret, maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

	while (1) {

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
}

/**
 * @param void *arg
 * @return void*
 */
static void *teavpn_thread_worker(void *arg)
{	
}

#undef BUFSIZE

/**
 * @param int sock_fd
 * @return void
 */
static bool teavpn_server_socket_setup(int sock_fd)
{
	int optval = 1;

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
		perror("setsockopt()");
		return false;
	}

	return true;
}

/**
 * @param char *dev
 * @return void
 */
static void teaserver_init_iface(server_config *config)
{
	char cmd1[100], cmd2[100], *escaped_dev, *escaped_inet4;

	escaped_dev = escapeshellarg(config->dev);
	escaped_inet4 = escapeshellarg(config->inet4);

	sprintf(cmd1, "/sbin/ip link set dev %s up mtu %d", escaped_dev, config->mtu);
	sprintf(cmd2, "/sbin/ip addr add dev %s %s broadcast 5.5.255.255", escaped_dev, escaped_inet4);

	free(escaped_dev);
	free(escaped_inet4);

	debug_log(1, "Executing: %s\n", cmd1);
	system(cmd1);

	debug_log(1, "Executing: %s\n", cmd2);
	system(cmd2);
}
