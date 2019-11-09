
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
static int16_t conn_count = 0;
static int16_t queue_count = 0;
static struct packet_queue *queue;
static struct buffer_channel *bufchan;
static struct worker_entry *dispatch_worker;
static struct connection_entry *connections;
static pthread_mutex_t accept_worker_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool teavpn_tcp_server_socket_setup(int sock_fd);
static bool teavpn_tcp_server_init_iface(server_config *config);
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);

/**
 * Worker that accepts new connection from client.
 */
static void *accept_worker_thread(void *x)
{
	pthread_mutex_lock(&accept_worker_mutex);

	while (true) {

	}

	pthread_mutex_unlock(&accept_worker_mutex);
	return NULL;
}

/**
 * Worker that dispatch data to client.
 */
static void *dispatch_worker_thread(uint64_t n)
{
	debug_log(2, "Spawning thread %ld...\n", n);
	while (true) {
		pthread_mutex_lock(&(dispatch_worker[n].mutex));
		pthread_cond_wait(&(dispatch_worker[n].cond), &(dispatch_worker[n].mutex));
		pthread_mutex_unlock(&(dispatch_worker[n].mutex));
	}

	return NULL;
}


/**
 * Get non-busy buffer channer index.
 */
static int16_t get_bufchan_index()
{
	static bool sleep_state = false;
	static uint8_t buf_chan_wait = 0;

	if (!conn_count) return 0;

	for (int16_t i = 0; i < conn_count; i++) {
		if (bufchan[i].ref_count == 0) {
			if (buf_chan_wait) buf_chan_wait--;
			return i;
		}
	}

	if (buf_chan_wait > 30) {
		sleep_state = true;
	} else {
		if (buf_chan_wait <= 100) buf_chan_wait++;
	}

	if (sleep_state) {
		debug_log(1, "Buffer channel got sleep state...\n");
		usleep(10000);
		buf_chan_wait--;
		if (buf_chan_wait <= 20) {
			debug_log(1, "Sleep state has been released\n");
			sleep_state = false;
		}
	}

	return -1;
}

/**
 * Add packet to the queue.
 */
static void insert_queue(struct buffer_channel *buf)
{
	if (queue_count == 0) {
		queues[0].free = false;
		queues[0].taken = false;
		queues[0].bufchan = buf;
		queues[0].conn_key = conn_key;
		queue_count++;
		return;
	}

	
}

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
	char config_buffer[4096];
	struct sockaddr_in server_addr;
	struct packet_queue _queue[QUEUE_AMOUNT];
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	struct connection_entry _connections[CONNECTION_ALLOC];

	queue = _queue;
	bufchan = _bufchan;
	connections = _connections;

	if (teavpn_tcp_server_init(config_buffer, config)) {
		return 1;
	}

	pthread_t dispatcher[config->threads];
	struct worker_entry _dispatch_worker[config->threads];

	// Init and lock all thread's mutex.
	dispatch_worker = _dispatch_worker;
	for (uint8_t i = 0; i < config->threads; ++i) {
		dispatch_worker[i].busy = false;
		dispatch_worker[i].queue = NULL;
		if (pthread_mutex_init(&(dispatch_worker[i].mutex), NULL)) {
			printf("Error: pthread_mutex_init\n");
			return 1;
		}
		pthread_mutex_lock(&(dispatch_worker[i].mutex));
		pthread_create(
			&(dispatch_worker[i].thread),
			NULL,
			(void * (*)(void *))dispatch_worker_thread,
			(void *)((uint64_t)(0ull | i))
		);
	}
	pthread_mutex_lock(&accept_worker_mutex);

	// Run accept worker.
	pthread_create(&accept_worker, NULL, accept_worker_thread, NULL);

	// Prepare server bind address data.
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);
	server_addr.sin_port = htons(config->bind_port);

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

	while (true) {

		max_fd = (tap_fd > pipe_fd[0]) ? tap_fd : pipe_fd[0];

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(pipe_fd[0], &rd_set);

		for (register int16_t i = 0; i < conn_count; i++) {
			if (connections[i].connected) {
				if (connections[i].fd > max_fd) {
					max_fd = connections[i].fd;
				}
				FD_SET(connections[i].fd, &rd_set);
			}
		}

		do {
			bufchan_index = get_bufchan_index();
		} while (bufchan_index == -1);

		fd_ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

		// Got interrupt signal.
		if ((fd_ret < 0) && (errno == EINTR)) {
			continue;
		}

		// Select error.
		if (fd_ret < 0) {
			perror("select()");
			continue;
		}

		#define packet ((teavpn_packet *)(bufchan[bufchan_index].buffer))

		// Read from server's tap_fd.
		if (FD_ISSET(tap_fd, &rd_set)) {
			nread = read(tap_fd, packet->data.data, TEAVPN_PACKET_BUFFER);
			debug_log(3, "Read from tap_fd %ld bytes\n", nread);

			if (nread < 0) {
				perror("Error read (tap_fd)");
				goto next_1;
			}

			packet->info.type = TEAVPN_PACKET_DATA;
			packet->info.len = nread;
			bufchan[bufchan_index].ref_count = conn_count;
			insert_queue(bufchan[bufchan_index]);
		}

		next_1:
		(void)1;

		#undef packet
	}

	return 0;
}

/**
 * Initialize TeaVPN server (socket, pipe, etc.)
 */
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config)
{
	// Initialize buffer channel value.
	for (int i = 0; i < BUFCHAN_ALLOC; ++i) {
		bufchan[i].ref_count = 0;
	}

	// Initialize connection entry value.
	for (uint8_t i = 0; i < CONNECTION_ALLOC; ++i) {
		connections[i].fd = -1;
		connections[i].connected = false;
		connections[i].error = 0;
		connections[i].seq = 0;
	}

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
