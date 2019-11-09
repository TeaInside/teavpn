
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
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn/teavpn.h>
#include <teavpn/helpers.h>
#include <teavpn/teavpn_server.h>
#include <teavpn/teavpn_config_parser.h>

extern char **_argv;
extern uint8_t verbose_level;

static int tap_fd;
static int net_fd;
static int pipe_fd[2];
static pthread_mutex_t accept_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *dispatcher_mutex;

static struct buffer_channel *bufchan;
static bool teavpn_tcp_server_init_iface(server_config *config);
static bool teavpn_tcp_server_socket_setup(int sock_fd);
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);

/**
 * Worker that accepts new connection from client.
 */
static void *accept_worker(void *x)
{
	pthread_mutex_lock(&accept_worker_mutex);

	while (true) {

	}

	pthread_mutex_unlock(&accept_worker_mutex);
}

/**
 * Main point of TeaVPN TCP Server.
 */
uint8_t teavpn_tcp_server(server_config *config)
{
	fd_set rd_set;
	char config_buffer[4096];
	struct sockaddr_in server_addr;
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	pthread_t accept_worker;

	bufchan = _bufchan;

	if (teavpn_tcp_server_init(config_buffer, config)) {
		return 1;
	}

	pthread_t dispatcher[config->threads];
	pthread_mutex_t _dispatcher_mutex[config->threads];

	dispatcher_mutex = _dispatcher_mutex;
	for (uint8_t i = 0; i < config->threads; ++i) {
		if (pthread_mutex_init(&(dispatcher_mutex[i]), NULL)) {
			printf("Error: pthread_mutex_init\n");
			return 1;
		}
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);
	server_addr.sin_port = htons(config->bind_port);

	// Lock all mutex.
	pthread_mutex_lock(&accept_worker_mutex);

	// Run accept worker.
	pthread_create(&accept_worker, NULL, accept_worker, NULL);

	// Bind socket to interface.
	if (bind(net_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Bind failed");
		close(net_fd);
		close(tap_fd);
		return 1;
	}

	// Listen
	if (listen(net_fd, 3) < 0) {
		perror("Listen failed");
		close(net_fd);
		close(tap_fd);
		return 1;
	}

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);
}

/**
 * Initialize TeaVPN server (socket, pipe, etc.)
 */
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config)
{
	if (config->config_file != NULL) {
		if (!teavpn_server_config_parser(config_buffer, config)) {
			printf("Config error!\n");
			return 1;
		}
	}

	verbose_level = config->verbose_level;

	if (config->data_dir == NULL) {
		printf("Data dir cannot be empty!\n");
		return 1;
	}

	if (pipe(pipe_fd) < 0) {
		perror("Cannot open pipe");
		return 1;
	}

	// Create TUN/TAP interface.
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully created a new interface \"%s\".\n", config->dev);

	// Initialize TUN/TAP interface.
	if (!teavpn_tcp_server_init_iface(config)) {
		printf("Cannot init interface\n");
		close(tap_fd);
		return 1;
	}

	// Create TCP socket.
	debug_log(1, "Creating TCP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "TCP socket created successfully\n");

	// Setting up socket.
	debug_log(1, "Setting up socket file descriptor...\n");
	if (!teavpn_tcp_server_socket_setup(net_fd)) {
		close(net_fd);
		close(tap_fd);
		return 1;
	}
	debug_log(1, "Socket file descriptor set up successfully\n");

	return 0;
}

/**
 * @param int sock_fd
 * @return void
 */
static bool teavpn_tcp_server_socket_setup(int sock_fd)
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
static bool teavpn_tcp_server_init_iface(server_config *config)
{
	char cmd1[100], cmd2[100],
		*escaped_dev,
		*escaped_inet4,
		*escaped_inet4_broadcast;

	escaped_dev = escapeshellarg(config->dev);
	escaped_inet4 = escapeshellarg(config->inet4);
	escaped_inet4_broadcast = escapeshellarg(config->inet4_broadcast);

	sprintf(
		cmd1,
		"/sbin/ip link set dev %s up mtu %d",
		escaped_dev,
		config->mtu
	);

	sprintf(
		cmd2,
		"/sbin/ip addr add dev %s %s broadcast %s",
		escaped_dev,
		escaped_inet4,
		escaped_inet4_broadcast
	);

	free(escaped_dev);
	free(escaped_inet4);
	free(escaped_inet4_broadcast);

	debug_log(0, "Executing: %s\n", cmd1);
	if (system(cmd1)) {
		return false;
	}

	debug_log(0, "Executing: %s\n", cmd2);
	if (system(cmd2)) {
		return false;
	}

	return true;
}
