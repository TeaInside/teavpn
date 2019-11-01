
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

#include <third_party/thpool/thpool.h>

#define MAX_CLIENT_ENTRY 30
#define BUFFER_CHANNEL_ENTRY 24

extern char **_argv;
extern uint8_t verbose_level;

static int tap_fd;
static int net_fd;
int16_t entry_count = 0;
struct buffer_channel *bufchan;
struct connection_entry *entries;

static int16_t get_buffer_channel_index();
static void *thread_worker(uint64_t entry);
static bool teavpn_server_socket_setup(int sock_fd);
static void teaserver_init_iface(server_config *dev);
static bool teavpn_client_auth(struct buffer_channel *bufchan, struct sockaddr_in *client_addr);

/**
 * @param server_config *config
 * @return uint8_t
 */
uint8_t teavpn_server(server_config *config)
{
	fd_set rd_set;
	ssize_t nwrite;
	int fd_ret, max_fd;
	int16_t bufchan_index;
	teavpn_packet *packet;
	threadpool threads_pool;
	char config_buffer[4096];
	uint64_t tap2net = 0, net2tap = 0;
	struct sockaddr_in server_addr, client_addr;
	socklen_t remote_len = sizeof(struct sockaddr_in);
	struct connection_entry _entries[MAX_CLIENT_ENTRY];
	struct buffer_channel _bufchan[BUFFER_CHANNEL_ENTRY];

	entries = _entries;
	bufchan = _bufchan;

	for (uint16_t i = 0; i < MAX_CLIENT_ENTRY; i++) {
		entries[i].connected = false;
	}

	for (uint64_t i = 0; i < BUFFER_CHANNEL_ENTRY; i++) {
		bufchan[i].bufptr = bufchan[i].buffer;
	}

	if (config->config_file != NULL) {
		if (!teavpn_server_config_parser(config_buffer, config)) {
			printf("Config error!\n");
			return 1;
		}
	}

	verbose_level = config->verbose_level;

	// Create TUN/TAP interface.
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully created a new interface \"%s\".\n", config->dev);

	// Initialize TUN/TAP interface.
	teaserver_init_iface(config);

	// Create UDP socket.
	debug_log(1, "Creating UDP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "UDP socket created successfully\n");

	debug_log(1, "Setting up socket file descriptor...\n");
	// Setting up socket.
	if (!teavpn_server_socket_setup(net_fd)) {
		return 1;
	}
	debug_log(1, "Socket file descriptor set up successfully\n");

	debug_log(1, "Intiailizing threads pool...\n");
	threads_pool = thpool_init(config->threads);
	debug_log(1, "Threads pool have been initialized\n");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);
	server_addr.sin_port = htons(config->bind_port);

	// Bind socket to interface.
	if (bind(net_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Bind failed");
		return 1;
	}

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	max_fd = (tap_fd > net_fd) ? tap_fd : net_fd;

	while (true) {

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(net_fd, &rd_set);

		do {
			bufchan_index = get_buffer_channel_index();
		} while (bufchan_index == -1);

		fd_ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

		if ((fd_ret < 0) && (errno == EINTR)) {
			continue;
		}

		if (fd_ret < 0) {
			perror("select()");
			continue;
		}

		if (FD_ISSET(tap_fd, &rd_set)) {
			bufchan_index = get_buffer_channel_index();
			bufchan[bufchan_index].length = read(tap_fd, bufchan[bufchan_index].buffer, UDP_BUFFER);
			bufchan[bufchan_index].ref_count = entry_count;

			printf("1 from tap_fd: %ld bytes\n", bufchan[bufchan_index].length);
			fflush(stdout);

			for (uint16_t i = 0; i < entry_count; i++) {
				if (entries[i].connected) {
					thpool_add_work(
						threads_pool,
						(void * (*)(void *))thread_worker,
						(void *)((uint64_t)(i | (bufchan_index << 16)))
					);	
				}
			}

			tap2net++;
		}

		if (FD_ISSET(net_fd, &rd_set)) {
			memset(&client_addr, 0, sizeof(client_addr));

			bufchan_index = get_buffer_channel_index();

			bufchan[bufchan_index].length = recvfrom(
				net_fd,
				bufchan[bufchan_index].buffer,
				UDP_BUFFER,
				MSG_WAITALL,
				(struct sockaddr *)&(client_addr),
				&remote_len
			);

			printf("read from net_fd: %ld bytes\n", bufchan[bufchan_index].length);
			fflush(stdout);

			if (bufchan[bufchan_index].length < 0) {
				perror("recvfrom");
				goto gcd;
			}

			packet = (teavpn_packet *)bufchan[bufchan_index].bufptr;

			if (packet->type == teavpn_packet_auth) {
				bufchan[bufchan_index].ref_count = 1;
				teavpn_client_auth(&(bufchan[bufchan_index]), &client_addr);
			} else if (packet->type == teavpn_packet_data) {

				nwrite = write(
					tap_fd,
					bufchan->bufptr + DATA_PACKET_OFFSET,
					packet->tot_len - DATA_PACKET_OFFSET
				);
				if (nwrite < 0) {
					perror("write tap_fd");
				}
				printf("written to tap_fd: %ld bytes\n", nwrite);
				fflush(stdout);

				bufchan[bufchan_index].ref_count = 0;
				for (uint16_t i = 0; i < entry_count; i++) {
					if (entries[i].connected) {
						bufchan[bufchan_index].ref_count++;
						thpool_add_work(
							threads_pool,
							(void * (*)(void *))thread_worker,
							(void *)((uint64_t)(i | (bufchan_index << 16)))
						);	
					}
				}
				net2tap++;
			}
		}

		printf("rok\n");
		fflush(stdout);

		gcd:
		(void)0;
	}
}

/**
 * @return int16_t
 */
static int16_t get_buffer_channel_index()
{
	for (int16_t i = 0; i < BUFFER_CHANNEL_ENTRY; ++i) {
		if (bufchan[i].ref_count == 0) {
			return i;
		}
	}

	// Buffer channels are all busy.
	return -1;
}

/**
 * @param uint64_t entry
 * @return void *
 */
static void *thread_worker(uint64_t entry)
{
	uint16_t
		bufchan_index = entry & 0xffff,
		conn_index = (entry >> 16) & 0xffff;

	ssize_t nbytes;
	char _connection_buffer[UDP_BUFFER + sizeof(teavpn_packet) + 24], *connection_buffer;
	teavpn_packet *packet = (teavpn_packet *)_connection_buffer;

	if ((*((uint32_t *)(&(entries[conn_index].info.sin_addr)))) == 0) {
		entries[conn_index].connected = false;
		printf("Client disconnected!\n");
		printf("conn_index: %d\n", conn_index);
		fflush(stdout);
		goto ret;
	}

	connection_buffer = &(_connection_buffer[DATA_PACKET_OFFSET]);
	packet->seq = 0;
	packet->type = teavpn_packet_data;
	packet->tot_len = DATA_PACKET_OFFSET + bufchan[bufchan_index].length;
	memcpy(connection_buffer, bufchan[bufchan_index].buffer, bufchan[bufchan_index].length);

	nbytes = sendto(
		net_fd,
		_connection_buffer,
		packet->tot_len,
		MSG_CONFIRM,
		(struct sockaddr *)&(entries[conn_index].info),
		sizeof(struct sockaddr_in)
	);

	debug_log(
		3,
		"sendto %s:%d (%ld bytes)\n",
		inet_ntoa(entries[conn_index].info.sin_addr),
		ntohs(entries[conn_index].info.sin_port),
		nbytes
	);

	if (nbytes < 0) {
		perror("sendto");
	}

	ret:
	bufchan[bufchan_index].ref_count--;
	return NULL;
}


static bool teavpn_client_auth(struct buffer_channel *bufchan, struct sockaddr_in *client_addr)
{
	bool ret = false;
	teavpn_packet packet;
	struct teavpn_client_auth auth;

	// write(1, &(bufchan->bufptr[DATA_PACKET_OFFSET]), bufchan->length);

	bufchan->bufptr += DATA_PACKET_OFFSET;
	memcpy(&(auth), bufchan->bufptr, sizeof(uint8_t) * 2);	
	auth.username = bufchan->bufptr + (sizeof(uint8_t) * 2);
	auth.password = bufchan->bufptr + (sizeof(uint8_t) * 2) + auth.username_len + 1;

	// // Debug only.
	// printf("username_len: %d\n", auth.username_len);
	// printf("password_len: %d\n", auth.password_len);
	// printf("username: \"%s\"\n", auth.username);
	// printf("password: \"%s\"\n", auth.password);

	if ((!strcmp(auth.username, "ammarfaizi2")) &&
		(!strcmp(auth.password, "testQWE123!@"))) {
		entries[entry_count].connected = true;
		entries[entry_count].send_counter = 0;
		entries[entry_count].recv_counter = 0;
		memcpy(&(entries[entry_count].info), client_addr, sizeof(struct sockaddr_in));
		entry_count++;
		ret = true;

		packet.seq = 0;
		packet.type = teavpn_packet_ack;
		packet.tot_len = sizeof(packet);
		strcpy(packet.data.ack, "ok");

		sendto(
			net_fd,
			&packet,
			sizeof(packet),
			MSG_CONFIRM,
			(struct sockaddr *)client_addr,
			sizeof(struct sockaddr_in)
		);
	}

	bufchan->bufptr = bufchan->buffer;
	bufchan->ref_count--;

	return ret;

	// struct client_auth auth;
	// teavpn_packet *packet;
	// char _username[255], _password[255];
	// static socklen_t remote_len = sizeof(struct sockaddr_in);

	// auth.username = _username;
	// auth.password = _password;

	// packet = (teavpn_packet *)bufchan->bufptr;
	// packet->data.auth = &auth;

	// bufchan->length = recvfrom(
	// 	net_fd,
	// 	packet->data.auth,
	// 	sizeof(uint8_t) * 2,
	// 	MSG_WAITALL,
	// 	(struct sockaddr *)client_addr,
	// 	&remote_len
	// );

	// bufchan->length = recvfrom(
	// 	net_fd,
	// 	packet->data.auth->username,
	// 	packet->data.auth->username_len,
	// 	MSG_WAITALL,
	// 	(struct sockaddr *)client_addr,
	// 	&remote_len
	// );
	// packet->data.auth->username[packet->data.auth->username_len] = '\0';

	// bufchan->length = recvfrom(
	// 	net_fd,
	// 	packet->data.auth->password,
	// 	packet->data.auth->password_len,
	// 	MSG_WAITALL,
	// 	(struct sockaddr *)client_addr,
	// 	&remote_len
	// );
	// packet->data.auth->password[packet->data.auth->password_len] = '\0';

	// if (
	// 	(!strcmp(packet->data.auth->username, "ammarfaizi2")) &&
	// 	(!strcmp(packet->data.auth->password, "test123qwe"))
	// ) {
	// 	entries[entry_count].connected = true;
	// 	entries[entry_count].send_counter = 0;
	// 	entries[entry_count].recv_counter = 0;
	// 	memcpy(&(entries[entry_count].info), client_addr, sizeof(struct sockaddr_in));
	// 	entry_count++;
	// }

	// #ifdef TEAVPN_DEBUG
	// 	printf("username length: %d\n", packet->data.auth->username_len);
	// 	printf("password length: %d\n", packet->data.auth->password_len);
	// 	printf("username: \"%s\"\n", packet->data.auth->username);
	// 	printf("password: \"%s\"\n", packet->data.auth->password);
	// 	fflush(stdout);
	// #endif
}

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

	debug_log(1, "Executing: %s\n", cmd1);
	system(cmd1);

	debug_log(1, "Executing: %s\n", cmd2);
	system(cmd2);
}
