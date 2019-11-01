
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

int net_fd;
struct sockaddr_in *server_addr;

/**
 * @param server_config *config
 * @return uint8_t
 */
uint8_t teavpn_client(client_config *config)
{
	fd_set rd_set;
	int fd_ret, max_fd, tap_fd;
	struct sockaddr_in _server_addr;
	socklen_t remote_len = sizeof(struct sockaddr_in);
	char connection_buffer[CONNECTION_BUFFER], config_buffer[4096];

	server_addr = &_server_addr;

	if (config->config_file != NULL) {
		if (!teavpn_client_config_parser(config_buffer, config)) {
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

	// Create UDP socket.
	debug_log(1, "Creating UDP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "UDP socket created successfully\n");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(config->server_ip);
	server_addr.sin_port = htons(config->server_port);

	debug_log(0, "Connecting to %s:%d...\n", config->server_ip, config->server_port);

	if (!teavpn_client_connect_auth(config)) {
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
	struct teavpn_client_auth auth;
	static socklen_t remote_len = sizeof(struct sockaddr_in);

	packet.type = teavpn_packet_auth;

	auth.seq = 0
	auth.username = config->username;
	auth.password = config->password;
	auth.username_len = config->username_len;
	auth.password_len = config->password_len;

	packet.data.auth = &auth;

	nbytes = sendto(
		net_fd,
		&(packet.type),
		sizeof(packet.type),
		MSG_CONFIRM,
		(struct sockaddr *)server_addr,
		remote_len
	);

	if (nbytes != sizeof(packet.type)) {
		perror("Error sendto");
		return false;
	}
}
