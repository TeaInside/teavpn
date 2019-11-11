
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
static uint64_t nqueue = 0;
static uint8_t thread_amount;
static int16_t conn_count = 0;
static uint16_t queue_amount = 0;
static struct worker_thread *workers;
static struct buffer_channel *bufchan;
static struct teavpn_tcp_queue *queues;
static struct connection_entry *connections;
static pthread_mutex_t global_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t global_mutex_b = PTHREAD_MUTEX_INITIALIZER;

static bool teavpn_tcp_server_socket_setup(int sock_fd);
static bool teavpn_tcp_server_init_iface(server_config *config);
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);

/**
 * Initialize connection entry.
 */
static void connection_entry_zero(int16_t i)
{
	connections[i].fd = -1;
	connections[i].connected = false;
	connections[i].error = 0;
	connections[i].seq = 0;
	connections[i].priv_ip = 0;
	memset(&(connections[i].addr), 0, sizeof(connections[i].addr));
}


/**
 * Trigger worker thread.
 */
static void teavpn_tcp_populate_queue()
{
	register uint16_t i, j = queue_amount;

	for (i = 0; i < QUEUE_AMOUNT; i++) {
		if (!j) break;
		if (!workers[i].busy) {
			pthread_cond_signal(&(workers[i].cond));
			j--;
		}
	}
}


/**
 * Enqueue data transmission.
 */
static void teavpn_tcp_enqueue(uint16_t conn_index, struct buffer_channel *bufchan)
{
	register uint8_t x = 0;
	while (true) {
		for (register uint16_t i = 0; i < QUEUE_AMOUNT; i++) {
			if (!queues[i].used) {
				queues[i].used = true;
				queues[i].taken = false;
				queues[i].queue_id = nqueue++;
				queues[i].conn_index = conn_index;
				queues[i].bufchan = bufchan;
				pthread_mutex_lock(&global_mutex_b);
				queue_amount++;
				bufchan->ref_count++;
				pthread_mutex_unlock(&global_mutex_b);
				return;
			}
		}
		usleep(1000);
		x++;
		if (x >= 3) {
			x = 0;
			teavpn_tcp_populate_queue();
		}
	}
}

/**
 * Worker thread.
 */
void *teavpn_tcp_worker_thread(struct worker_thread *x)
{
	register uint16_t i;
	register ssize_t nwrite;
	register bool has_job = false;

	while (true) {
		pthread_mutex_lock(&(x->mutex));
		pthread_cond_wait(&(x->cond), &(x->mutex));

		x->busy = true;

		for (i = 0; i < QUEUE_AMOUNT; ++i) {
			if (queues[i].used && (!queues[i].taken)) {
				pthread_mutex_lock(&global_mutex_a);
				queues[i].taken = true;
				has_job = true;
				pthread_mutex_unlock(&global_mutex_a);
				break;
			}
		}

		if (has_job) {
			#define packet ((teavpn_packet *)(bufchan->buffer))

			packet->info.seq = connections[queues[i].conn_index].seq++;

			nwrite = write(
				connections[queues[i].conn_index].fd,
				packet,
				packet->info.len
			);

			debug_log(2, "Write to client %ld bytes\n", nwrite);

			if (nwrite == 0) {
				close(connections[queues[i].conn_index].fd);
				connection_entry_zero(queues[i].conn_index);
			} else if (nwrite < 0) {
				connections[queues[i].conn_index].error++;
				if (connections[queues[i].conn_index].error > MAX_CLIENT_ERR) {
					close(connections[queues[i].conn_index].fd);
					connection_entry_zero(queues[i].conn_index);
				}
				perror("Error write to client");
			}

			pthread_mutex_lock(&global_mutex_b);
			queue_amount--;
			queues[i].bufchan->ref_count--;
			pthread_mutex_unlock(&global_mutex_b);

			#undef packet
		}

		x->busy = false;

		pthread_mutex_unlock(&(x->mutex));
	}


	return NULL;
}


/**
 * Get non-busy connection entry.
 */
static int16_t get_free_connection_index()
{
	if (!conn_count) return 0;

	for (int i = 0; i < CONNECTION_ALLOC; i++) {
		if (!connections[i].connected) {
			return i;
		}
	}

	return -1;
}

/**
 * Get non-busy buffer channel index.
 */
static int16_t get_bufchan_index()
{
	static bool sleep_state = false;
	static uint8_t buf_chan_wait = 0;

	if (!conn_count) return 0;

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
 * Validate username and password format.
 */
static bool validate_auth(struct teavpn_packet_auth *auth)
{
	/// Min/max username length.
	if ((auth->username_len < 4) || (auth->username_len > 64)) {
		return false;
	}

	// Min password length.
	if ((auth->password_len < 6)) {
		return false;
	}

	// Make sure the username is null terminated.
	for (register uint16_t i = 0; i < 256; ++i) {
		if (auth->username[i] == '\0') {
			goto password_validate;
		}
	}
	return false;


	password_validate:
	// Make sure the password is null terminated.
	for (register uint16_t i = 0; i < 256; ++i) {
		if (auth->password[i] == '\0') {
			return true;
		}
	}
	return false;
}

/**
 * Worker which accepts new connection.
 */
static void *teavpn_tcp_accept_worker_thread(server_config *config)
{
	FILE *h;
	int client_fd;
	char *remote_addr;
	int16_t conn_index;
	uint16_t remote_port;
	teavpn_packet packet;
	ssize_t nread, nwrite;
	struct sockaddr_in client_addr;
	socklen_t rlen = sizeof(struct sockaddr_in);

	while (true) {

		// Set client_addr to zero.
		memset(&client_addr, 0, sizeof(client_addr));

		conn_index = get_free_connection_index();

		client_fd = accept(net_fd, (struct sockaddr *)&(client_addr), &rlen);
		if (client_fd < 0) {
			perror("Error accept");
			goto next_d;
		}

		remote_addr = inet_ntoa(client_addr.sin_addr);
		remote_port = ntohs(client_addr.sin_port);

		if (conn_index == -1) {
			debug_log(1, "Connection is full, cannot accept more client.\n");
			close(client_fd);
		} else {

			debug_log(1, "Accepting a connection from %s:%d\n", remote_addr, remote_port);

			nread = read(client_fd, &(packet), sizeof(packet));

			if (nread < 0) {
				printf("Error read from %s:%d\n", remote_addr, remote_port);
				perror("Error read client after accept");
				fflush(stdout);
				close(client_fd);
				goto next_d;
			}

			if (nread == 0) {
				close(client_fd);
				goto next_d;
			}

			// Got auth packet.
			if ((packet.info.type == TEAVPN_PACKET_AUTH) && (packet.info.seq == 0)) {
				if (!validate_auth(&(packet.data.auth))) {
					close(client_fd);
				}

				// Debug only.
				#if 1
				printf("Username length: %d\n", packet.data.auth.username_len);
				printf("Password length: %d\n", packet.data.auth.password_len);
				printf("Username: \"%s\"\n", packet.data.auth.username);
				printf("Password: \"%s\"\n\n", packet.data.auth.password);
				fflush(stdout);
				#endif

				h = teavpn_auth_check(config, &(packet.data.auth));
				if (h) {
					char buffer[64];
					size_t len, sp = 0;
					const uint8_t sig = 0xff;

					memset(buffer, 0, sizeof(buffer));
					fgets(buffer, 63, h);
					len = strlen(buffer);

					while (buffer[sp] != ' ') {
						if (sp >= len) {
							fclose(h);
							close(client_fd);
							connection_entry_zero(conn_index);
							debug_log(1, "Invalid ip configuration for username %s", packet.data.auth.username);
							goto next_d;
						}
						sp++;
					}

					if ((sp > sizeof("xxx.xxx.xxx.xxx/xx")) || ((len - (sp - 1)) > sizeof("xxx.xxx.xxx.xxx"))) {
						fclose(h);
						close(client_fd);
						connection_entry_zero(conn_index);
						debug_log(1, "Invalid ip configuration for username %s", packet.data.auth.username);
						goto next_d;	
					}

					debug_log(1, "%s connected from (%s:%d) [%s]\n",
						packet.data.auth.username,
						remote_addr,
						remote_port,
						buffer
					);

					connections[conn_index].fd = client_fd;
					connections[conn_index].priv_ip = ip_read_conv(buffer);
					connections[conn_index].error = 0;
					connections[conn_index].seq = 1;
					connections[conn_index].addr = client_addr;

					// Prepare packet.
					packet.info.type = TEAVPN_PACKET_SIG;
					packet.info.len = OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig);
					packet.info.seq = 0;
					packet.data.sig.sig = TEAVPN_SIG_AUTH_OK;
					nwrite = write(client_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig));
					fclose(h);
					if (nwrite < 0) {
						close(client_fd);
						connection_entry_zero(conn_index);
						perror("Error write to client after accept");
						goto next_d;
					}

					memcpy(packet.data.conf.inet4, buffer, sp);
					packet.data.conf.inet4[sp] = '\0';
					strcpy(packet.data.conf.inet4_broadcast, &(buffer[sp+1]));

					#ifdef TEAVPN_DEBUG
					printf("inet4: \"%s\"\n", packet.data.conf.inet4);
					printf("inet4_bc: \"%s\"\n", packet.data.conf.inet4_broadcast);
					fflush(stdout);
					#endif

					nread = read(client_fd, buffer, 64);

					// Prepare packet.
					packet.info.type = TEAVPN_PACKET_CONF;
					packet.info.len = OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig);

					nwrite = write(client_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.conf));
					if (nwrite < 0) {
						close(client_fd);
						connection_entry_zero(conn_index);
						perror("Error write to client after accept");
						goto next_d;
					}

					connections[conn_index].connected = true;
					conn_count++;
					write(m_pipe_fd[1], &sig, sizeof(sig));
				} else {
					// Prepare packet.
					packet.info.type = TEAVPN_PACKET_SIG;
					packet.info.len = OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig);
					packet.info.seq = 0;
					packet.data.sig.sig = TEAVPN_SIG_AUTH_REJECT;
					nwrite = write(client_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig));
					if (nwrite < 0) {
						perror("Error write to client after accept");
						close(client_fd);
						goto next_d;
					}
				}
			}
		}

		next_d:
		(void)1;
	}

	return NULL;
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
	uint64_t tap2net = 0, net2tap = 0;
	struct teavpn_tcp_queue _queues[QUEUE_AMOUNT];
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	struct connection_entry _connections[CONNECTION_ALLOC];

	queues = _queues;
	bufchan = _bufchan;
	connections = _connections;

	if (teavpn_tcp_server_init(config_buffer, config)) {
		return 1;
	}

	thread_amount = config->threads;
	struct worker_thread _workers[config->threads];
	workers = _workers;

	for (register uint8_t i = 0; i < config->threads; ++i) {
		char thread_name[] = "teavpn_tcp_worker_xxx";
		workers[i].busy = false;
		pthread_cond_init(&(workers[i].cond), NULL);
		pthread_mutex_init(&(workers[i].mutex), NULL);
		pthread_create(
			&(workers[i].thread),
			NULL,
			(void * (*)(void *))teavpn_tcp_worker_thread,
			(void *)&(workers[i])
		);
		sprintf(thread_name, "teavpn_tcp_worker_%d", i);
		pthread_setname_np(workers[i].thread, thread_name);
		pthread_detach(workers[i].thread);
	}

	// Prepare server bind address data.
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(config->bind_port);
	server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);

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

	pthread_create(
		&accept_worker,
		NULL,
		(void * (*)(void *))teavpn_tcp_accept_worker_thread,
		(void *)config
	);
	pthread_setname_np(accept_worker, "accept-worker");
	pthread_detach(accept_worker);

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	while (true) {

		max_fd = (((tap_fd > net_fd) && (tap_fd > m_pipe_fd[0])) ? tap_fd :
				(net_fd > m_pipe_fd[0]) ? net_fd : m_pipe_fd[0]);

		FD_ZERO(&rd_set);
		FD_SET(net_fd, &rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(m_pipe_fd[0], &rd_set);

		for (register int16_t i = 0; i < conn_count; i++) {
			if (connections[i].connected) {
				if (connections[i].fd > max_fd) {
					max_fd = connections[i].fd;
				}
				FD_SET(connections[i].fd, &rd_set);
			}
		}

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

		// Read from tap_fd.
		if (FD_ISSET(tap_fd, &rd_set)) {
			do {
				bufchan_index = get_bufchan_index();
			} while (bufchan_index == -1);

			packet->info.type = TEAVPN_PACKET_DATA;
			nread = read(tap_fd, packet->data.data, TEAVPN_TAP_READ_SIZE);
			bufchan[bufchan_index].len = packet->info.len = OFFSETOF(teavpn_packet, data) + nread;

			debug_log(3, "Read from fd %ld bytes\n", nread);

			if (nread < 0) {
				perror("Error read from tap_fd");
				goto next_1;
			}
			tap2net++;

			register int16_t i, q = 0;
			for (i = 0; i < conn_count; i++) {
				if (connections[i].connected) {
					q++;
					teavpn_tcp_enqueue(i, &(bufchan[bufchan_index]));
				}
			}
			teavpn_tcp_populate_queue();
		}

		// Read data from client.
		next_1:
		for (register int16_t i = 0; i < conn_count; i++) {
			if (FD_ISSET(connections[i].fd, &rd_set)) {
				if (connections[i].connected) {
					do {
						bufchan_index = get_bufchan_index();
					} while (bufchan_index == -1);

					nread = read(connections[i].fd, packet, TEAVPN_PACKET_BUFFER);

					// Connection closed by client.
					if (nread == 0) {
						FD_CLR(connections[i].fd, &rd_set);
						close(connections[i].fd);
						connection_entry_zero(i);
						printf("Connection closed.\n");
						goto next_2;
					}

					if (nread < 0) {
						connections[i].error++;
						perror("Error read from connection fd");
						if (connections[i].error > MAX_CLIENT_ERR) {
							FD_CLR(connections[i].fd, &rd_set);
							close(connections[i].fd);
							connection_entry_zero(i);
						}
						goto next_2;
					}

					if (packet->info.type == TEAVPN_PACKET_DATA) {
						net2tap++;
						nwrite = write(tap_fd, &(packet->data), packet->info.len - OFFSETOF(teavpn_packet, data));
						if (nwrite < 0) {
							connections[i].error++;
							perror("Error write to tap_fd");
						}

						debug_log(3, "Write to fd %ld bytes\n", nwrite);
					}

				} else {
					FD_CLR(connections[i].fd, &rd_set);
					close(connections[i].fd);
					connection_entry_zero(i);
				}
			}
		}

		// New connection is made.
		next_2:
		if (FD_ISSET(m_pipe_fd[0], &rd_set)) {
			uint8_t sig;
			read(m_pipe_fd[0], &sig, sizeof(sig));
		}

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
	for (register uint16_t i = 0; i < BUFCHAN_ALLOC; ++i) {
		bufchan[i].ref_count = 0;
	}

	// Initialize queues.
	for (register uint16_t  i = 0; i < QUEUE_AMOUNT; ++i) {
		queues[i].used = false;
		queues[i].queue_id = -1;
		queues[i].conn_index = -1;
		queues[i].bufchan = NULL;
	}

	// Initialize connection entry value.
	for (register uint16_t i = 0; i < CONNECTION_ALLOC; ++i) {
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

	if (pipe(m_pipe_fd) < 0) {
		perror("Cannot open pipe for m_pipe_fd");
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
