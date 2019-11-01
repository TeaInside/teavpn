
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
#include <teavpn/teavpn_client.h>
#include <teavpn/teavpn_config_parser.h>

extern uint8_t verbose_level;

static bool teavpn_client_connect_auth(client_config *config);

static int net_fd;
static int tap_fd;
struct sockaddr_in *server_addr;

/**
 * @param server_config *config
 * @return uint8_t
 */
uint8_t teavpn_client(client_config *config)
{
	fd_set rd_set;
	int fd_ret, max_fd;
	teavpn_packet *packet;
	ssize_t nread, nwrite;
	struct sockaddr_in _server_addr;
	socklen_t remote_len = sizeof(struct sockaddr_in);
	char _connection_buffer[CONNECTION_BUFFER], config_buffer[4096], *connection_buffer;

	packet = (teavpn_packet *)_connection_buffer;
	connection_buffer = &(_connection_buffer[DATA_PACKET_OFFSET]);

	server_addr = &_server_addr;

	if (config->config_file != NULL) {
		if (!teavpn_client_config_parser(config_buffer, config)) {
			printf("Config error!\n");
			return 1;
		}
	}

	if (config->server_ip == NULL) {
		printf("Error: server_ip is not set!\n");
		return 1;
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

	// Create UDP socket.
	debug_log(1, "Creating UDP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		close(tap_fd);
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "UDP socket created successfully\n");

	memset(server_addr, 0, sizeof(*server_addr));
	server_addr->sin_family = AF_INET;
	server_addr->sin_addr.s_addr = inet_addr(config->server_ip);
	server_addr->sin_port = htons(config->server_port);

	debug_log(0, "Connecting to %s:%d...\n", config->server_ip, config->server_port);

	if (!teavpn_client_connect_auth(config)) `{
		close(net_fd);
		close(tap_fd);
		printf("Connection failed!\n");
		return 1;
	}

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	max_fd = (tap_fd > net_fd) ? tap_fd : net_fd;
	while (true) {
		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(net_fd, &rd_set);

		fd_ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);

		if ((fd_ret < 0) && (errno == EINTR)) {
			continue;
		}

		if (fd_ret < 0) {
			perror("select()");
			continue;
		}

		if (FD_ISSET(tap_fd, &rd_set)) {
			nread = read(tap_fd, connection_buffer, CONNECTION_BUFFER);
			if (nread < 0) {
				perror("read tap_fd");
				goto a11;
			}
			packet->seq = 0;
			packet->type = teavpn_packet_data;
			packet->tot_len = DATA_PACKET_OFFSET + nread;

			nwrite = sendto(
				net_fd,
				_connection_buffer,
				packet->tot_len,
				MSG_CONFIRM,
				(struct sockaddr *)server_addr,
				remote_len
			);
			if (nwrite < 0) {
				perror("sendto net_fd");
				goto a11;
			}

			printf("sent %ld bytes\n", nwrite);
			fflush(stdout);
		}

		a11:
		if (FD_ISSET(net_fd, &rd_set)) {
			nread = recvfrom(
				net_fd,
				_connection_buffer,
				UDP_BUFFER,
				MSG_WAITALL,
				(struct sockaddr *)server_addr,
				&remote_len
			);
			if (nread < 0) {
				perror("recvfrom net_fd");
				goto a12;
			}

			printf("got %ld bytes\n", nread);
			fflush(stdout);

			nwrite = write(tap_fd, connection_buffer, packet->tot_len - DATA_PACKET_OFFSET);
			if (nwrite < 0) {
				perror("write tap_fd");
				goto a12;
			}
		}

		a12:
		(void)0;
	}
}

/**
 * @param client_config *config
 * @return bool
 */
static bool teavpn_client_connect_auth(client_config *config)
{
	ssize_t nbytes;
	teavpn_packet packet;
	char _payload[4096], *lptr;
	struct teavpn_client_auth auth;
	static socklen_t remote_len = sizeof(struct sockaddr_in);

	packet.seq = 0;
	packet.type = teavpn_packet_auth;

	auth.username = config->username;
	auth.password = config->password;
	auth.username_len = config->username_len;
	auth.password_len = config->password_len;

	packet.data.auth = &auth;

	memcpy(_payload, &packet, sizeof(packet.seq) + sizeof(packet.type));
	packet.tot_len = sizeof(packet.seq) + sizeof(packet.type);
	lptr = &(_payload[packet.tot_len]);
	packet.tot_len += sizeof(packet.tot_len);

	memcpy(&(_payload[packet.tot_len]), &(packet.data.auth->username_len), sizeof(uint8_t));
	packet.tot_len += sizeof(uint8_t);

	memcpy(&(_payload[packet.tot_len]), &(packet.data.auth->password_len), sizeof(uint8_t));
	packet.tot_len += sizeof(uint8_t);

	memcpy(&(_payload[packet.tot_len]), auth.username, auth.username_len + 1);
	packet.tot_len += auth.username_len + 1;

	memcpy(&(_payload[packet.tot_len]), auth.password, auth.password_len + 1);
	packet.tot_len += auth.password_len + 1;

	memcpy(lptr, &packet.tot_len, sizeof(uint16_t));

	// // Debug only.
	// printf("username_len: %d\n", auth.username_len);
	// printf("password_len: %d\n", auth.password_len);
	// fflush(stdout);
	// write(1, _payload, packet.tot_len);

	nbytes = sendto(
		net_fd,
		_payload,
		packet.tot_len,
		MSG_CONFIRM,
		(struct sockaddr *)server_addr,
		remote_len
	);

	if (nbytes != packet.tot_len) {
		perror("Error sendto");
		return false;
	}

	memset(&packet, 0, sizeof(packet));

	lptr = _payload;
	nbytes = recvfrom(
		net_fd,
		lptr,
		UDP_BUFFER,
		MSG_WAITALL,
		(struct sockaddr *)server_addr,
		&remote_len	
	);

	if ((((teavpn_packet *)lptr)->type) == teavpn_packet_ack) {
		if (!strcmp(((teavpn_packet *)lptr)->data.ack, "ok")) {
			printf("Connected to the server!\n");
			return true;
		} else {
			printf("Server rejected the connection!\n");
		}
	}

	printf("Couldn't conenct to the server\n");
	return false;
}

