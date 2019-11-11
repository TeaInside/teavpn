
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
static int a_pipe_fd[2];
static int16_t conn_count = 0;
static struct buffer_channel *bufchan;
static struct connection_entry *connections;

static bool teavpn_tcp_server_socket_setup(int sock_fd);
static bool teavpn_tcp_server_init_iface(server_config *config);
static uint8_t teavpn_tcp_server_init(char *config_buffer, server_config *config);


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
 * Get non-busy buffer channer index.
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
static void *accept_worker_thread()
{
	int client_fd;
	uint8_t signal;
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

		// Waiting for signal from parent.
		if (read(a_pipe_fd[0], &signal, sizeof(signal)) < 0) {
			perror("Error read from a_pipe_fd");
			continue;
		}

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

			printf("nread: %ld\n", nread);

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

				// Prepare packet.
				packet.info.type = TEAVPN_PACKET_SIG;
				packet.info.len = sizeof(packet.data.sig);
				packet.info.seq = 0;
				packet.data.sig.sig = TEAVPN_SIG_AUTH_OK;
				nwrite = write(client_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.sig));
				if (nwrite < 0) {
					perror("Error write to client after accept");
					close(client_fd);
					goto next_d;
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
	struct buffer_channel _bufchan[BUFCHAN_ALLOC];
	struct connection_entry _connections[CONNECTION_ALLOC];

	bufchan = _bufchan;
	connections = _connections;

	if (teavpn_tcp_server_init(config_buffer, config)) {
		return 1;
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

	pthread_create(&accept_worker, NULL, accept_worker_thread, NULL);
	pthread_setname_np(accept_worker, "accept-worker");

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	max_fd = (
		((tap_fd > net_fd) && (tap_fd > m_pipe_fd[0])) ? tap_fd :
			(net_fd > m_pipe_fd[0]) ? net_fd : m_pipe_fd[0]
	);

	while (true) {
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

		// Accept new connection.
		if (FD_ISSET(net_fd, &rd_set)) {
			const uint8_t a_pipe_signal = 0xff;
			if (write(a_pipe_fd[1], &a_pipe_signal, sizeof(a_pipe_signal)) < 0) {
				perror("Error write to a_pipe_fd");
			}
		}

		// Read from tap_fd.
		if (FD_ISSET(tap_fd, &rd_set)) {
			nread = read(tap_fd, bufchan[bufchan_index].buffer, TEAVPN_TAP_READ_SIZE);
			if (nread < 0) {
				perror("Error read from tap_fd");
				goto next_1;
			}
			tap2net++;
		}

		// Read data from client.
		next_1:
		for (register int16_t i = 0; i < conn_count; i++) {
			if (FD_ISSET(connections[i].fd, &rd_set)) {
				if (connections[i].connected) {

					do {
						bufchan_index = get_bufchan_index();
					} while (bufchan_index == -1);

					nread = read(connections[i].fd, bufchan[bufchan_index].buffer, TEAVPN_PACKET_BUFFER);

					if (nread < 0) {
						connections[i].error++;
						perror("Error read from connection fd");
						if (connections[i].error > 15) {
							connections[i].connected = false;
							FD_CLR(connections[i].fd, &rd_set);
							connections[i].fd = -1;
						}
						continue;
					}

					net2tap++;
					bufchan[bufchan_index].len = nread;

				} else {
					FD_CLR(connections[i].fd, &rd_set);
				}
			}
		}
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

	if (pipe(m_pipe_fd) < 0) {
		perror("Cannot open pipe for m_pipe_fd");
		return 1;
	}

	if (pipe(a_pipe_fd) < 0) {
		perror("Cannot open pipe for a_pipe_fd");
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
