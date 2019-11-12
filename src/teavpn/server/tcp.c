
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
static uint16_t conn_count = 0;
static struct teavpn_tcp_queue *queues;
static struct buffer_channel *bufchan;
static struct connection_entry *connections;
static struct worker_thread *workers;
static pthread_cond_t accept_worker_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t accept_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t worker_job_pull_mutex = PTHREAD_MUTEX_INITIALIZER;

static void enqueue_packet(uint16_t conn, uint16_t bufchan_index);
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

		#define thread_name (bufchan[0].buffer)
		sprintf(thread_name, "teavpn-worker-%d", i);
		pthread_setname_np(workers[i].thread, thread_name);
		#undef thread_name
	}
	memset(bufchan[0].buffer, 0, sizeof("teavpn-worker-xxx"));

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
		goto close_server;
	}

	/**
	 * Listen
	 */
	if (listen(net_fd, 3) < 0) {
		debug_log(0, "Listen socket failed");
		perror("Listen failed");
		goto close_server;
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

	debug_log(0, "Listening on %s:%d...", config->bind_addr, config->bind_port);

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
		 * Get buffer channel index.
		 */
		do {
			bufchan_index = get_bufchan_index();
		} while (bufchan_index == -1);


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
			for (register uint16_t i = 0; i < CONNECTION_ALLOC; i++) {
				if (connections[i].connected) {
					/**
					 * Insert write queue.
					 *
					 * Send bufchan_index to connection i.
					 */
					enqueue_packet(i, bufchan_index);
				}
			}
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
						debug_log(1, "(%s:%d) connection closed",
							inet_ntoa(connections[i].addr.sin_addr),
							ntohs(connections[i].addr.sin_port)
						);
						connection_zero(i);
						continue;
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

						continue;
					}


					/**
					 * Write to TUN/TAP server.
					 */
					if (packet->info.type == TEAVPN_PACKET_DATA) {

						while (nread < (packet->info.len)) {
							register ssize_t tmp_nread;
							debug_log(3, "Read extra %ld/%ld bytes", nread, packet->info.len);
							tmp_nread = read(
								connections[i].fd,
								&(((char *)packet)[nread]),
								packet->info.len - nread
							);

							if (tmp_nread < 0) {
								connections[i].error++;
								perror("Error read extra");
							} else {
								nread += tmp_nread;
							}
						}

						connections[i].seq++;
						debug_log(3, "[%ld] Read from client %s:%d (server_seq: %ld) (client_seq: %ld) (seq %s)",
							connections[i].seq,
							inet_ntoa(connections[i].addr.sin_addr),
							ntohs(connections[i].addr.sin_port),
							connections[i].seq,
							packet->info.seq,
							(connections[i].seq == packet->info.seq) ? "match" : "invalid"
						);

						nwrite = write(tap_fd, &(packet->data.data), nread - TEAVPN_PACK(0));
						if (nwrite < 0) {
							connections[i].error++;
							perror("Error write to tap_fd");
							continue;
						}

						debug_log(3, "Write to tap_fd %ld bytes", nwrite);

					} else {
						connections[i].error++;
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

		if (FD_ISSET(net_fd, &rd_set)) {
			pthread_cond_signal(&accept_worker_cond);
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
 * Pull job from thread.
 */
static int16_t worker_job_pull()
{
	pthread_mutex_lock(&worker_job_pull_mutex);
	for (register int16_t i = 0; i < QUEUE_AMOUNT; ++i) {
		if ((queues[i].used) && (!queues[i].taken)) {
			queues[i].taken = true;
			pthread_mutex_unlock(&worker_job_pull_mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&worker_job_pull_mutex);
	return -1;
}


/**
 * Add queue.
 */
static void enqueue_packet(uint16_t conn, uint16_t bufchan_index)
{
	while (true) {
		for (register int16_t i = 0; i < QUEUE_AMOUNT; ++i) {
			if (!queues[i].used) {
				queues[i].used = true;
				queues[i].taken = false;
				queues[i].conn_index = conn;
				queues[i].bufchan = bufchan[bufchan_index];
				return;
			}
		}
		debug_log(0, "Packet queue is full");
	}
}


/**
 * Worker which dispatches data to clients.
 */
static void *teavpn_tcp_worker_thread(struct worker_thread *worker)
{

	#define packet ((teavpn_packet *)(bufchan.buffer))

	register uint16_t i;
	while (true) {
		pthread_mutex_lock(&(worker->mutex));
		pthread_cond_wait(&(worker->cond), &(worker->mutex));


		packet->info.seq = ++(connections[i].seq);
		nwrite = write(connections[i].fd, packet, TEAVPN_PACK(nread));

		debug_log(3, "[%ld] Write to client %s:%d %ld bytes (server_seq: %ld) (client_seq: %ld) (seq %s)",
			connections[i].seq,
			inet_ntoa(connections[i].addr.sin_addr),
			ntohs(connections[i].addr.sin_port),
			nwrite,
			connections[i].seq,
			packet->info.seq,
			(connections[i].seq == packet->info.seq) ? "match" : "invalid"
		);

		/**
		 * Connection closed by client.
		 */
		if (nwrite == 0) {
			FD_CLR(connections[i].fd, &rd_set);
			close(connections[i].fd);
			debug_log(1, "(%s:%d) connection closed",
				inet_ntoa(connections[i].addr.sin_addr),
				ntohs(connections[i].addr.sin_port)
			);
			connection_zero(i);
			continue;
		}


		if (nwrite < 0) {
			char *remote_addr = inet_ntoa(connections[i].addr.sin_addr);
			uint16_t remote_port = ntohs(connections[i].addr.sin_port);

			debug_log(0, "Error write to %s:%d", remote_addr, remote_port);
			perror("Error write to connection fd");

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
		}

		pthread_mutex_unlock(&(worker->mutex));
	}
	return NULL;
}



/**
 * Get index of free connection entry.
 */
static int16_t get_free_conn_index()
{
	for (int16_t i = 0; i < CONNECTION_ALLOC; ++i) {
		if (!connections[i].connected) {
			return i;
		}
	}

	return -1;
}


/**
 * Worker which accepts new connection.
 */
static void *teavpn_tcp_accept_worker_thread(server_config *config)
{
	FILE *h;
	int client_fd;
	uint64_t seq = 0;
	char *remote_addr;
	int16_t conn_index;
	uint16_t remote_port;
	teavpn_packet packet;
	ssize_t nread, nwrite;
	struct timeval timeout;
	struct sockaddr_in client_addr;
	socklen_t rlen = sizeof(struct sockaddr_in);

	/**
	 * NDF
	 */
	char buffer[64 + OFFSETOF(teavpn_packet, data)], *pbuf;
	size_t len, sp = 0;
	const uint8_t sig = 0xff;


	/**
	 * Set timeout to 10 seconds.
	 */
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;


	while (true) {

		pthread_mutex_lock(&accept_worker_mutex);
		pthread_cond_wait(&accept_worker_cond, &accept_worker_mutex);

		/**
		 * Set client_addr to zero.
		 */
		seq = 0;
		memset(&client_addr, 0, sizeof(client_addr));

		client_fd = accept(net_fd, (struct sockaddr *)&client_addr, &rlen);

		if (client_fd < 0) {
			debug_log(0, "Error on accept");
			perror("Error on accept");
			goto next_cycle;
		}

		remote_addr = inet_ntoa(client_addr.sin_addr);
		remote_port = ntohs(client_addr.sin_port);

		debug_log(3, "%s:%d is attempting to make a connection...", remote_addr, remote_port);

		conn_index = get_free_conn_index();

		if (conn_index == -1) {
			debug_log(0, "Connection entry is full, cannot accept more client");
			debug_log(0, "Dropping connection from %s:%d...", remote_addr, remote_port);
			close(client_fd);
			goto next_cycle;
		}

		/**
		 * Set recv timeout.
		 */
		if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
			debug_log(0, "Error set recv timeout");
			perror("Error set recv timeout");
			goto next_cycle;
		}

		/**
		 * Set send timeout.
		 */
		if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
			debug_log(0, "Error set recv timeout");
			perror("Error set recv timeout");
			goto next_cycle;
		}

		/**
		 * Read auth packet (username and password).
		 */
		seq++; // seq 1
		nread = read(client_fd, &packet, sizeof(packet));

		debug_log(3, "[%ld] Read auth packet from %s:%d %ld bytes (server_seq: %ld) (client_seq: %ld) (seq %s)",
				seq, remote_addr, remote_port, nread, seq, packet.info.seq,
				(seq == packet.info.seq) ? "match" : "invalid");

		if (nread == 0) {
			debug_log(3, "Client %s:%d closed connection");
			close(client_fd);
			goto next_cycle;
		}

		if (nread < 0) {
			debug_log(3, "An error occured when reading auth packet from %s:%d", remote_addr, remote_port);
			perror("Error read from client (acceptor)");
			close(client_fd);
			goto next_cycle;
		}

		if (seq != packet.info.seq) {
			debug_log(0, "Invalid packet sequence from %s:%d (client_seq: %ld) (server_seq: %ld)",
				remote_addr, remote_port, seq, packet.info.seq);
			close(client_fd);
			goto next_cycle;
		}

		/**
		 * Validate credential from auth packet.
		 */
		if (packet.info.type == TEAVPN_PACKET_AUTH) {
			h = teavpn_auth_check(config, &(packet.data.auth));
		} else {
			debug_log(3, "Invalid auth packet from %s:%d", remote_addr, remote_port);
			debug_log(3, "Dropping connection from %s:%d...", remote_addr, remote_port);
			close(client_fd);
			goto next_cycle;
		}

		if (h == NULL) {
			/**
			 * Invalid username or password.
			 */
			packet.info.type = TEAVPN_PACKET_SIG;
			packet.info.len = TEAVPN_PACK(sizeof(packet.data.sig));
			packet.info.seq = ++seq; // seq 2
			packet.data.sig.sig = TEAVPN_SIG_AUTH_REJECT;
			nwrite = write(client_fd, &packet, TEAVPN_PACK(sizeof(packet.data.sig)));
			debug_log(3, "Invalid username or password from %s:%d", remote_addr, remote_port);
			debug_log(3, "Dropping connection from %s:%d...", remote_addr, remote_port);
			close(client_fd);
			goto next_cycle;
		}


		/**
		 * Preparing client network interface configuration.
		 */

		memset(buffer, 0, sizeof(buffer));
		pbuf = fgets(buffer, 63, h);
		fclose(h);
		if (pbuf == NULL) {
			debug_log(0, "Invalid IP configuration for username %s", packet.data.auth.username);
		}

		len = strlen(buffer);

		while (buffer[sp] != ' ') {
			if (sp >= len) {
				close(client_fd);
				debug_log(0, "Invalid IP configuration for username %s", packet.data.auth.username);
				goto next_cycle;
			}
			sp++;
		}

		if ((sp > sizeof("xxx.xxx.xxx.xxx/xx")) || ((len - (sp - 1)) > sizeof("xxx.xxx.xxx.xxx"))) {
			close(client_fd);
			debug_log(0, "Invalid IP configuration for username %s", packet.data.auth.username);
			goto next_cycle;	
		}

		debug_log(1, "%s connected from (%s:%d) [%s]", packet.data.auth.username, remote_addr, remote_port, buffer);


		/**
		 * Assign client fd to connection entry.
		 */
		connections[conn_index].fd = client_fd;
		connections[conn_index].priv_ip = ip_read_conv(buffer);
		connections[conn_index].error = 0;
		connections[conn_index].addr = client_addr;


		/**
		 * Send auth ok signal.
		 */
		packet.info.type = TEAVPN_PACKET_SIG;
		packet.info.len = TEAVPN_PACK(sizeof(packet.data.sig));
		packet.data.sig.sig = TEAVPN_SIG_AUTH_OK;
		packet.info.seq = ++seq; // seq 2

		nwrite = write(client_fd, &packet, TEAVPN_PACK(sizeof(packet.data.sig)));

		debug_log(3, "[%ld] Write sig auth to %s:%d %ld bytes (server_seq: %ld) (client_seq: %ld) (seq %s)",
				seq, remote_addr, remote_port, nwrite, seq, packet.info.seq,
				(seq == packet.info.seq) ? "match" : "invalid");

		if (nwrite == 0) {
			debug_log(3, "Client %s:%d closed connection (authenticated)", remote_addr, remote_port);
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}

		if (nwrite < 0) {
			debug_log(3, "Error send auth ok signal to %s:%d", remote_addr, remote_port);
			perror("Error write to client_fd (acceptor)");
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}


		/**
		 * Wait for ack signal.
		 */
		seq++; // seq 3
		nread = read(client_fd, &packet, sizeof(packet));

		debug_log(3, "[%ld] Read sig ack from %s:%d %ld bytes (server_seq: %ld) (client_seq: %ld) (seq %s)",
				seq, remote_addr, remote_port, nread, seq, packet.info.seq,
				(seq == packet.info.seq) ? "match" : "invalid");

		if (nread == 0) {
			debug_log(3, "Client %s:%d closed connection (authenticated)", remote_addr, remote_port);
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}

		if (nread < 0) {
			debug_log(3, "Error read ack packet from %s:%d", remote_addr, remote_port);
			perror("Error read from client_fd (acceptor)");
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}

		if (seq != packet.info.seq) {
			debug_log(0, "Invalid packet sequence from %s:%d (client_seq: %ld) (server_seq: %ld) (authenticated)",
				remote_addr, remote_port, seq, packet.info.seq);
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}

		/**
		 * Verify ack signal..
		 */
		if ((packet.info.type == TEAVPN_PACKET_SIG) && (packet.data.sig.sig == TEAVPN_SIG_ACK)) {
			debug_log(3, "[%ld] Got ack from %s:%d (connection established)", seq, remote_addr, remote_port);
		} else {
			debug_log(3, "[%ld] Invalid ack signal from %s:%d (authenticated)", seq, remote_addr, remote_port);
			debug_log(0, "Dropping connection from %s:%d...", remote_addr, remote_port);
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}


		/**
		 * Send network interface configuration.
		 */
		packet.info.type = TEAVPN_PACKET_CONF;
		packet.info.seq = ++seq; // seq 4
		packet.info.len = TEAVPN_PACK(sizeof(packet.data.conf));
		memcpy(packet.data.conf.inet4, buffer, sp);
		packet.data.conf.inet4[sp] = '\0';
		strcpy(packet.data.conf.inet4_broadcast, &(buffer[sp+1]));
		nwrite = write(client_fd, &packet, TEAVPN_PACK(sizeof(packet.data.conf)));

		debug_log(3, "[%ld] Write packet conf to %s:%d %ld bytes (server_seq: %ld) (client_seq: %ld) (seq %s)",
				seq, remote_addr, remote_port, nwrite, seq, packet.info.seq,
				(seq == packet.info.seq) ? "match" : "invalid");

		if (nwrite == 0) {
			debug_log(3, "Client %s:%d closed connection (authenticated)", remote_addr, remote_port);
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}

		if (nwrite < 0) {
			debug_log(3, "Error send network config to %s:%d", remote_addr, remote_port);
			perror("Error write to client_fd (acceptor)");
			close(client_fd);
			connection_zero(conn_index);
			goto next_cycle;
		}


		/**
		 * Set entry to connected state.
		 */
		connections[conn_index].connected = true;
		connections[conn_index].seq = seq;
		conn_count++;


		/**
		 * Interrupt main process in order to read rd_set.
		 */
		nwrite = write(m_pipe_fd[1], &sig, sizeof(sig));
		if (nwrite < 0) {
			debug_log(0, "Error write to m_pipe_fd[1]");
			perror("Error write to m_pipe_fd[1]");
			goto next_cycle;
		}

		next_cycle:
		(void)1;
		pthread_mutex_unlock(&accept_worker_mutex);
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

