
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

static bool teavpn_tcp_client_init_iface(client_config *config);
static bool teavpn_tcp_client_init(char *config_buffer, client_config *config);

static void print_err_sig(uint8_t sig)
{
	switch (sig) {
		case TEAVPN_SIG_AUTH_REJECT:
			printf("Invalid username or password\n");
			break;
		case TEAVPN_SIG_UNKNOWN:
			printf("Invalid error (code: TEAVPN_SIG_AUTH_UNKNOWN)\n");
			break;
		case TEAVPN_SIG_DROP:
			printf("Connection dropped!\n");
			break;
		case TEAVPN_SIG_AUTH_OK:
		default:
			break;
	}
}

uint8_t teavpn_tcp_client(client_config *config)
{
	fd_set rd_set;
	int fd_ret, max_fd;
	teavpn_packet packet;
	ssize_t nwrite, nread;
	char config_buffer[4096];
	uint64_t tap2net = 0, net2tap = 0;

	#define server_addr ((struct sockaddr_in *)&(packet.data.data))

	if (teavpn_tcp_client_init(config_buffer, config)) {
		return 1;
	}

	// Prepare server address.
	memset(server_addr, 0, sizeof(struct sockaddr_in));
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(config->server_port);
	server_addr->sin_addr.s_addr = inet_addr(config->server_ip);

	debug_log(0, "Connecting to %s:%d...\n", config->server_ip, config->server_port);
	if (connect(net_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0) {
		perror("Error connect");
		goto close;
	}

	// Prepare auth packet.
	packet.info.type = TEAVPN_PACKET_AUTH;
	packet.info.len = sizeof(struct teavpn_packet_auth);
	packet.info.seq = 0;
	packet.data.auth.username_len = config->username_len;
	packet.data.auth.password_len = config->password_len;
	strcpy(packet.data.auth.username, config->username);
	strcpy(packet.data.auth.password, config->password);

	#ifdef TEAVPN_DEBUG
	printf("username: \"%s\"\n", packet.data.auth.username);
	printf("password: \"%s\"\n", packet.data.auth.password);
	fflush(stdout);
	#endif

	nwrite = write(net_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.auth));
	if (nwrite < 0) {
		perror("Error write");
		goto close;
	}

	nread = read(net_fd, &packet, sizeof(packet));
	if (packet.info.type == TEAVPN_PACKET_SIG) {
		if (packet.data.sig.sig == TEAVPN_SIG_AUTH_OK) {
			printf("Auth OK\n");
		} else {
			print_err_sig(packet.data.sig.sig);
			goto close;
		}
	}

	

	close:
	fflush(stdout);
	close(net_fd);
	close(tap_fd);
	return 1;

	#undef server_addr
}

static bool teavpn_tcp_client_init(char *config_buffer, client_config *config)
{
	if (config->config_file != NULL) {
		if (!teavpn_client_config_parser(config_buffer, config)) {
			printf("Config error!\n");
			return 1;
		}
	}

	if (config->username == NULL) {
		printf("username cannot be empty\n");
		return 1;
	}

	if (config->username_len >= 64) {
		printf("Invalid username length\n");
		return 1;
	}

	if (config->password == NULL) {
		printf("password cannot be empty\n");
		return 1;
	}

	if (config->server_ip == NULL) {
		printf("server_ip cannot be empty\n");
		return 1;
	}

	if (config->server_port == 0) {
		printf("server_port cannot be zero\n");
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


	// Create TCP socket.
	debug_log(1, "Creating TCP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		close(tap_fd);
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "TCP socket created successfully\n");


	return 0;
}


static bool teavpn_tcp_client_init_iface(client_config *config)
{
	return true;
}
