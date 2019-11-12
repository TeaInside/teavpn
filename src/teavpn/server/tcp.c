
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
static struct teavpn_tcp_queue *queues;
static struct buffer_channel *bufchan;
static struct connection_entry *connections;
static struct worker_thread *workers;

static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);
static void *teavpn_tcp_accept_worker_thread(server_config *config);
static void *teavpn_tcp_worker_thread(struct worker_thread *worker);
static int16_t get_bufchan_index();
static void queue_zero(register uint16_t i);
static void connection_zero(register uint16_t i);
static bool teavpn_tcp_server_socket_setup(int sock_fd);
static bool teavpn_tcp_server_init_iface(server_config *config);


/**
 * Main point of TeaVPN TCP Server.
 */
__attribute__((force_align_arg_pointer)) uint8_t teavpn_tcp_server(server_config *config)
{
	fd_set rd_set;
	int  fd_ret, max_fd;
	ssize_t nwrite, nread;
	int16_t bufchan_index;
	pthread_t accept_worker;
	struct sockaddr_in server_addr;
	struct teavpn_tcp_queue _queues[QUEUE_AMOUNT];
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	struct connection_entry _connections[CONNECTION_ALLOC];

	/**
	 * To store config file buffer (parsing).
	 *
	 * Avoid to use heap as long as it
	 * is still eligible to use stack.
	 *
	 * (heap is slower than stack)
	 */
	char config_buffer[4096];

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

	/**
	 * Prepare worker threads.
	 * (Threads which transmit data to client).
	 *
	 * Use stack allocation as long as possible.
	 */
	struct worker_thread _workers[thread_amount];
	workers = _workers;

	if (thread_amount < 3) {
		debug_log(0, "Minimal threads amount is 3, but %d given", thread_amount);
		goto close_server;
	}


	/**
	 * Create the worker threads.
	 */
	for (register uint8_t i = 0; i < config->threads; ++i) {
		char thread_name[] = "teavpn-worker_xxx";
		workers[i].busy = false;
		workers[i].num = i;
		pthread_cond_init(&(workers[i].cond), NULL);
		pthread_mutex_init(&(workers[i].mutex), NULL);
		pthread_create(
			&(workers[i].thread),
			NULL,
			(void * (*)(void *))teavpn_tcp_worker_thread,
			(void *)&(workers[i])
		);
		pthread_detach(workers[i].thread);
		sprintf(thread_name, "teavpn-worker-%d", i);
		pthread_setname_np(workers[i].thread, thread_name);
	}

	/**
	 * Prepare server bind address data.
	 */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(config->bind_port);
	server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);

	/**
	 * Bind socket to address.
	 */
	if (bind(net_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		debug_log(0, "Bind socket failed");
		perror("Bind failed");
		close(net_fd);
		close(tap_fd);
		return 1;
	}

	/**
	 * Listen
	 */
	if (listen(net_fd, 3) < 0) {
		debug_log(0, "Listen socket failed");
		perror("Listen failed");
		close(net_fd);
		close(tap_fd);
		return 1;
	}

	/**
	 * Ignore SIGPIPE
	 */
	signal(SIGPIPE, SIG_IGN);

	/**
	 * Create accept worker thread.
	 * (Thread which accepts new connection).
	 */
	pthread_create(
		&accept_worker,
		NULL,
		(void * (*)(void *))teavpn_tcp_accept_worker_thread,
		(void *)config
	);
	pthread_setname_np(accept_worker, "accept-worker");
	pthread_detach(accept_worker);

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	/**
	 * TeaVPN server event loop.
	 */
	while (true) {

		/**
		 * Calculate maximum value between tap_fd, net_fd and m_pie_fd[0].
		 */
		max_fd = (((tap_fd > net_fd) && (tap_fd > m_pipe_fd[0])) ? tap_fd :
				(net_fd > m_pipe_fd[0]) ? net_fd : m_pipe_fd[0]);

		/**
		 * Set rd_set to zero.
		 *
		 * This is a compulsory step in using
		 * select(2) inside of an event loop.
		 */
		FD_ZERO(&rd_set);

		/**
		 * Add file descriptors to rd_set.
		 */
		FD_SET(net_fd, &rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(m_pipe_fd[0], &rd_set);


		/**
		 * Add all connected clients file descriptor to rd_set.
		 */
		for (register uint16_t i = 0; i < CONNECTION_ALLOC; i++) {
			if (connections[i].connected) {

				/**
				 * Recalculate max fd to make sure that max_fd
				 * has the maximum value from the entire involved
				 * file descriptors.
				 */
				if (connections[i].fd > max_fd) {
					max_fd = connections[i].fd;
				}

				/**
				 * Add file descriptors to rd_set.
				 */
				FD_SET(connections[i].fd, &rd_set);
			}
		}

		/**
		 * Block main process until there is one or more ready fd.
		 * Read `man 2 select_tut` for details.
		 */
		fd_ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

		/**
		 * Got interrupt signal.
		 */
		if ((fd_ret < 0) && (errno == EINTR)) {
			debug_log(2, "select(2) got interrupt signal");
			continue;
		}

		/**
		 * Got an error.
		 */
		if (fd_ret < 0) {
			debug_log(0, "select(2) got an error");
			perror("select()");
			continue;
		}

		/**
		 * Create a macro to manage buffer channel as other data type.
		 *
		 * Don't make a new variable as long as we can use the available
		 * resources in safely way.
		 */
		#define packet ((teavpn_packet *)(bufchan[bufchan_index].buffer))


		/**
		 * Read data from server TUN/TAP.
		 */
		if (FD_ISSET(tap_fd, &rd_set)) {

			/**
			 * Get buffer channel index.
			 */
			do {
				bufchan_index = get_bufchan_index();
			} while (bufchan_index == -1);

			/**
			 * Read from TUN/TAP.
			 */
			nread = read(tap_fd, packet->data.data, TEAVPN_TAP_READ_SIZE);
			if (nread < 0) {
				debug_log(0, "Error read from tap_fd");
				perror("Error read from tap_fd");
				goto next_1;
			}

			packet->info.type = TEAVPN_PACKET_DATA;
			packet->info.len = TEAVPN_PACK(nread);
		}


		next_1:
		/**
		 * Traverse clients fd and read data from clients.
		 */
		for (register uint16_t i = 0; i < CONNECTION_ALLOC; i++) {
			if (connections[i].connected) {
				if (FD_ISSET(connections[i].fd, &rd_set)) {

					/**
					 * Get buffer channel index.
					 */
					do {
						bufchan_index = get_bufchan_index();
					} while (bufchan_index == -1);

					nread = read(connections[i].fd, packet, TEAVPN_PACKET_BUFFER);

					/**
					 * Connection closed by client.
					 */
					if (nread == 0) {
						FD_CLR(connections[i].fd, &rd_set);
						close(connections[i].fd);
						connection_zero(i);
						debug_log(1, "(%s:%d) connection closed",
							inet_ntoa(connections[i].addr.sin_addr),
							ntohs(connections[i].addr.sin_port)
						);
						goto next_2;
					}

					/**
					 * Error read from client fd.
					 */
					if (nread < 0) {
						char *remote_addr = inet_ntoa(connections[i].addr.sin_addr);
						uint16_t remote_port = ntohs(connections[i].addr.sin_port);

						debug_log(0, "Error read from (%s:%d)", remote_addr, remote_port);
						perror("Error read from connection fd");

						/**
						 * Increment the error counter.
						 */
						connections[i].error++;

						/**
						 * Force disconnect client if it has
						 * reached the max number of errors.
						 */
						if (connections[i].error > MAX_CLIENT_ERR) {
							debug_log(0,
								"Client %s:%d has been disconnected because it has reached the max number of errors",
								remote_port,
								remote_port
							);
							FD_CLR(connections[i].fd, &rd_set);
							close(connections[i].fd);
							connection_zero(i);
						}

						goto next_2;
					}

				}
			}
		}


		next_2:
		/**
		 * Deal with new connection.
		 */
		if (FD_ISSET(m_pipe_fd[0], &rd_set)) {
			uint8_t sig_x;

			nread = read(m_pipe_fd[0], &sig_x, sizeof(sig_x));
			if (nread < 0) {
				debug_log(0, "Error read from m_pipe_fd[0]");
				perror("Error read from m_pipe_fd[0]");
			}
		}

		/**
		 * Since macro doesn't have scope limit, we have to undef here
		 * so that it doesn't distrub the outer scope of variable usage.
		 */
		#undef packet
	}

	close_server:
	close(m_pipe_fd[0]);
	close(m_pipe_fd[1]);
	close(net_fd);
	close(tap_fd);
	return 1;
}



/**
 * Worker which dispatches data to clients.
 */
static void *teavpn_tcp_worker_thread(struct worker_thread *worker)
{
	while (true) {
		pthread_mutex_lock(&(worker->mutex));
		pthread_cond_wait(&(worker->cond), &(worker->mutex));

		pthread_mutex_unlock(&(worker->mutex));
	}
	return NULL;
}



/**
 * Worker which accepts new connection.
 */
static void *teavpn_tcp_accept_worker_thread(server_config *config)
{
	int client_fd;
	char *remote_addr;
	uint16_t remote_port;
	struct sockaddr_in client_addr;
	socklen_t rlen = sizeof(struct sockaddr_in);

	while (true) {

		// Set client_addr to zero.
		memset(&client_addr, 0, sizeof(client_addr));

		client_fd = accept(net_fd, (struct sockaddr *)&client_addr, &rlen);

		if (client_fd < 0) {
			debug_log(0, "Error on accept");
			perror("Error on accept");
			continue;
		}

		remote_addr = inet_ntoa(client_addr.sin_addr);
		remote_port = ntohs(client_addr.sin_port);
	}
	return NULL;
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
		debug_log(0, "Cannot open pipe for m_pipe_fd");
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
		debug_log(0, "Cannot create TCP socket");
		perror("Socket creation failed");
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
		debug_log(0, "Cannot setup socket");
		close(m_pipe_fd[0]);
		close(m_pipe_fd[1]);
		close(net_fd);
		close(tap_fd);
		return 1;
	}
	debug_log(1, "Socket file descriptor set up successfully");

	return 0;
}


/**
 * Get non-busy buffer channel index.
 */
static int16_t get_bufchan_index()
{
	static bool sleep_state = false;
	static uint8_t buf_chan_wait = 0;

	for (int16_t i = 0; i < BUFCHAN_ALLOC; i++) {
		if (bufchan[i].ref_count == 0) {
			if (buf_chan_wait > 0) buf_chan_wait--;
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
 * Initialize network interface for TeaVPN server.
 *
 * @param server_config *config
 * @return bool
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

	debug_log(0, "Executing: %s", cmd1);
	if (system(cmd1)) {
		return false;
	}

	debug_log(0, "Executing: %s", cmd2);
	if (system(cmd2)) {
		return false;
	}

	return true;
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

