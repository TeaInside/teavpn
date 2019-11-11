
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#define _GNU_SOURCE

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
static int m_pipe_fd[2];
static uint8_t thread_amount;

static void queue_zero(register uint16_t i);
static void connection_zero(register uint16_t i);
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);

/**
 * Main point of TeaVPN TCP Server.
 */
uint8_t teavpn_tcp_server(server_config *config)
{
	fd_set rd_set;
	int max_fd, fd_ret;
	ssize_t nwrite, nread;
	int16_t bufchan_index;
	pthread_t accept_worker;

	/**
	 * To store config file buffer (parsing).
	 *
	 * Avoid to use heap as long as it
	 * is still eligible to use stack.
	 *
	 * (heap is slower than stack)
	 */
	char config_buffer[4096];

	struct sockaddr_in server_addr;
	uint64_t tap2net = 0, net2tap = 0;
	struct teavpn_tcp_queue _queues[QUEUE_AMOUNT];
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	struct connection_entry _connections[CONNECTION_ALLOC];

	/** 
	 * Assign internal stack allocation to global vars
	 * in order to make other threads can access them.
	 */
	queues = _queues;
	bufchan = _bufchan;
	connections = _connections;

	/**
	 * Initialize TeaVPN server (vars, socket, iface, etc.)
	 */
	if (teavpn_tcp_server_init(config_buffer, config)) {
		return 1;
	}

	thread_amount = config->threads;
	if (thread_amount < 3) {
		debug_log(0, "");
		goto close_server;
	}

	close_server:
	close(net_fd);
	close(tap_fd);
	return 1;
}

/**
 * Set queue entry to zero (clean up).
 */
static void queue_zero(register uint16_t i)
{
	queues[i].used = false;
	queues[i].queue_id = -1;
	queues[i].conn_index = -1;
	queues[i].bufchan = NULL;
}

/**
 * Set connection entry to zero (clean up).
 */
static void connection_zero(register uint16_t i)
{
	connections[i].fd = -1;
	connections[i].connected = false;
	connections[i].error = 0;
	connections[i].seq = 0;
	connections[i].priv_ip = 0;
	memset(&(connections[i].addr), 0, sizeof(connections[i].addr));
	memset(&(connections[i].mutex), 0, sizeof(connections[i].mutex));
	pthread_mutex_init(&(connections[i].mutex), NULL);
}


/**
 * Initialize TeaVPN server (socket, pipe, etc.)
 */
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config)
{
	// Initialize buffer channel value.
	for (register uint16_t i = 0; i < BUFCHAN_ALLOC; ++i) {
		bufchan[i].ref_count = 0;
	}

	// Initialize queues.
	for (register uint16_t  i = 0; i < QUEUE_AMOUNT; ++i) {
		queue_zero(i);
	}

	// Initialize connection entry value.
	for (register uint16_t i = 0; i < CONNECTION_ALLOC; ++i) {
		connection_zero(i);
	}

	// Load config file.
	if (config->config_file != NULL) {
		if (!teavpn_server_config_parser(config_buffer, config)) {
			debug_log(0, "Config error!");
			return 1;
		}
	}

	// Set verbose_level (global var).
	verbose_level = config->verbose_level;

	// data_dir is a directory that saves TeaVPN data
	// such as user, password, etc.
	if (config->data_dir == NULL) {
		debug_log(0, "Data dir cannot be empty!");
		return 1;
	}

	/**
	 * This pipe is purposed to interrupt main
	 * process when a new connection is made.
	 */
	if (pipe(m_pipe_fd) < 0) {
		debug_log("Cannot open pipe for m_pipe_fd");
		perror("Cannot open pipe for m_pipe_fd");
		return 1;
	}

	/**
	 * Create TUN/TAP interface.
	 */
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		debug_log(0, "Error connecting to TUN/TAP interface \"%s\"!", config->dev);
		close(m_pipe_fd[0]);
		close(m_pipe_fd[1]);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully created a new interface \"%s\".", config->dev);

	/**
	 * Initialize TUN/TAP interface.
	 */
	if (!teavpn_tcp_server_init_iface(config)) {
		debug_log(0, "Cannot init interface");
		close(m_pipe_fd[0]);
		close(m_pipe_fd[1]);
		close(tap_fd);
		return 1;
	}

	/**
	 * Create TCP socket.
	 */
	debug_log(1, "Creating TCP socket...");
	if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation failed");
		debug_log(0, "Cannot create TCP socket");
		close(m_pipe_fd[0]);
		close(m_pipe_fd[1]);
		close(tap_fd);
		return 1;
	}
	debug_log(1, "TCP socket created successfully");

	/**
	 * Setting up socket.
	 */
	debug_log(1, "Setting up socket file descriptor...");
	if (!teavpn_tcp_server_socket_setup(net_fd)) {
		close(m_pipe_fd[0]);
		close(m_pipe_fd[1]);
		close(net_fd);
		close(tap_fd);
		return 1;
	}
	debug_log(1, "Socket file descriptor set up successfully");

	return 0;
}
