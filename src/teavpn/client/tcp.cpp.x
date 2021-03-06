
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

extern char **_argv;
extern uint8_t verbose_level;

static int tap_fd;
static int net_fd;
static bool teavpn_client_init_iface(client_config *config, struct teavpn_client_ip *ip);

static int read_n(int fd, char *buf, int n) {
	int nread, left = n;
	while (left > 0) {
		if ((nread = read(fd, buf, left)) == 0){
			return 0;
		} else {
			left -= nread;
			buf += nread;
		}
	}
	return n;  
}

/**
 * @param client_config *config
 * @return uint8_t
 */
uint8_t teavpn_tcp_client(client_config *config)
{
	fd_set rd_set;
	int fd_ret, max_fd;
	ssize_t nwrite, nread;
	char config_buffer[4096];
	struct teavpn_packet packet;
	uint64_t tap2net = 0, net2tap = 0;
	#define auth ((struct teavpn_packet_auth *)packet.data)
	#define server_addr ((struct sockaddr_in *)&(config_buffer[2048]))
	#define client_ip ((struct teavpn_client_ip *)packet.data)

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
		printf("server_ip cannot be zero\n");
		return 1;
	}

	auth->username_len = config->username_len;
	auth->password_len = config->password_len;
	strcpy(auth->username, config->username);
	strcpy(auth->password, config->password);

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

	memset(server_addr, 0, sizeof(struct sockaddr_in));
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(config->server_port);
	server_addr->sin_addr.s_addr = inet_addr(config->server_ip);

	debug_log(0, "Connecting to %s:%d...\n", config->server_ip, config->server_port);
	if (connect(net_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0) {
		perror("Error connect");
		goto close;
	}

	packet.info.type = TEAVPN_PACKET_AUTH;
	packet.info.len = sizeof(struct teavpn_packet_auth);
	packet.info.seq = 0;

	#ifdef TEAVPN_DEBUG
	// printf("username: \"%s\"\n", auth->username);
	// printf("password: \"%s\"\n", auth->password);
	// fflush(stdout);
	#endif

	nwrite = write(net_fd, &packet, sizeof(struct packet_info) + sizeof(struct teavpn_packet_auth));
	if (nwrite < 0) {
		perror("Error write");
		goto close;
	}

	nread = read(net_fd, &packet, sizeof(struct packet_info) + sizeof(struct teavpn_client_ip));
	if (nread < 0) {
		perror("Error read");
		goto close;
	}

	if (packet.info.type != TEAVPN_PACKET_ACK) {
		printf("Invalid username or password!\n");
		goto close;
	}

	#ifdef TEAVPN_DEBUG
	printf("inet4: \"%s\"\n", client_ip->inet4);
	printf("inet4_broadcast: \"%s\"\n", client_ip->inet4_broadcast);
	fflush(stdout);
	#endif

	if (!teavpn_client_init_iface(config, client_ip)) {
		printf("Cannot init interface\n");
		close(tap_fd);
		return 1;
	}

	max_fd = (tap_fd > net_fd) ? tap_fd : net_fd;
	packet.info.type = TEAVPN_PACKET_DATA;

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
			tap2net++;

			nread = read(tap_fd, &(packet.data), TEAVPN_PACKET_BUFFER);
			debug_log(3, "read from tap_fd %ld bytes\n", nread);
			if (nread < 0) {
				perror("Error read tap_fd");
				goto next;
			}

			packet.info.len = sizeof(packet.info) + nread;
			printf("packet_len: %d\n", packet.info.len);

			nwrite = write(net_fd, &packet, packet.info.len);
			if (nwrite < 0) {
				perror("Error write net_fd");
				goto next;
			}
		}

		next:
		if (FD_ISSET(net_fd, &rd_set)) {
			net2tap++;

			nread = read(net_fd, &packet, TEAVPN_PACKET_BUFFER);
			if (nread < 0) {
				perror("Error read net_fd");
				goto next_2;
			}

			// if (nread < packet.info.len) {
			// 	nread += read(net_fd, ((char *)&packet) + nread, TEAVPN_PACKET_BUFFER);
			// }

			// read_n(net_fd, packet.data, packet.info.len);

			// printf("packet type: %d\n",packet.info.type);
			if (packet.info.type == TEAVPN_PACKET_DATA) {
				nwrite = write(tap_fd, packet.data, nread - sizeof(packet.info));
				debug_log(3, "write to tap_fd %ld bytes\n", nwrite);

				if (nwrite < 0) {
					perror("Error write tap_fd");
					goto next_2;
				}
			}
		}

		next_2:
		(void)0;
	}

	close:
	close(net_fd);
	close(tap_fd);
	return 1;

	#undef server_addr
	#undef client_ip
	#undef auth
}

/**
 * @param client_config *config
 * @param struct teavpn_client_ip *ip
 * @return void
 */
static bool teavpn_client_init_iface(client_config *config, struct teavpn_client_ip *ip)
{
	bool ret;
	char cmd[100],
		data[100],
		*escaped_dev,
		*escaped_inet4,
		*escaped_inet4_broadcast,
		*p, *q;
	FILE *fp = NULL;

	escaped_dev = escapeshellarg(config->dev);
	escaped_inet4 = escapeshellarg(ip->inet4);
	escaped_inet4_broadcast = escapeshellarg(ip->inet4_broadcast);

	/**
	 * Set interface up.
	 */
	sprintf(
		cmd,
		"/sbin/ip link set dev %s up mtu %d",
		escaped_dev,
		config->mtu
	);
	debug_log(1, "Executing: %s\n", cmd);
	if (system(cmd)) {
		ret = false;
		goto ret;
	}


	/**
	 * Assign private IP.
	 */
	sprintf(
		cmd,
		"/sbin/ip addr add dev %s %s broadcast %s",
		escaped_dev,
		escaped_inet4,
		escaped_inet4_broadcast
	);
	debug_log(1, "Executing: %s\n", cmd);
	if (system(cmd)) {
		ret = false;
		goto ret;
	}

	/**
	 * Get server route data.
	 */
	sprintf(cmd, "/sbin/ip route get %s", config->server_ip);
	debug_log(1, "Executing: %s\n", cmd);
	fp = popen(cmd, "r");
	fgets(data, 99, fp);
	pclose(fp);

	p = strstr(data, "via");
	if (p == NULL) {
		printf("Cannot get server route via\n");
		ret = false;
		goto ret;
	}
	while ((*p) != ' ') p++;
	p++;
	q = p;
	while ((*q) != ' ') q++;
	*q = '\0';


	sprintf(cmd, "/sbin/ip route add %s/32 via %s", config->server_ip, p);
	debug_log(1, "Executing: %s\n", cmd);
	system(cmd);

	sprintf(cmd, "/sbin/ip route add 0.0.0.0/1 via %s", "5.5.0.1");
	debug_log(1, "Executing: %s\n", cmd);
	system(cmd);

	sprintf(cmd, "/sbin/ip route add 128.0.0.0/1 via %s", "5.5.0.1");
	debug_log(1, "Executing: %s\n", cmd);
	system(cmd);

	ret = true;
ret:
	free(escaped_dev);
	free(escaped_inet4);
	free(escaped_inet4_broadcast);
	return ret;
}
