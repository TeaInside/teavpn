
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

static bool teavpn_tcp_client_init(char *config_buffer, client_config *config);
static bool teavpn_client_init_iface(client_config *config, struct teavpn_client_ip *ip);

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
	uint64_t tap2net = 0, net2tap = 0, seq = 0;

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
	packet.info.len = OFFSETOF(teavpn_packet, data) + sizeof(struct teavpn_packet_auth);
	packet.data.auth.username_len = config->username_len;
	packet.data.auth.password_len = config->password_len;
	strcpy(packet.data.auth.username, config->username);
	strcpy(packet.data.auth.password, config->password);

	#ifdef TEAVPN_DEBUG
	printf("username: \"%s\"\n", packet.data.auth.username);
	printf("password: \"%s\"\n", packet.data.auth.password);
	fflush(stdout);
	#endif

	packet.info.seq = ++seq; // 1
	nwrite = write(net_fd, &packet, OFFSETOF(teavpn_packet, data) + sizeof(packet.data.auth));
	debug_log(3, "Auth data sent (%ld bytes)\n", nwrite);
	if (nwrite < 0) {
		perror("Error write");
		goto close;
	}

	nread = read(net_fd, &packet, sizeof(packet));
	if (packet.info.type == TEAVPN_PACKET_SIG) {

		seq++; // Must be 2
		if (packet.info.seq != seq) {
			printf("Invalid seq number (server_seq: %ld) (client_seq: %ld)\n", packet.info.seq, seq);
			goto close;
		}

		if (packet.data.sig.sig == TEAVPN_SIG_AUTH_OK) {
			printf("Auth OK\n");
		} else {
			print_err_sig(packet.data.sig.sig);
			goto close;
		}
	} else {
		printf("Invalid\n");
		goto close;
	}

	packet.info.seq = ++seq; // 3
	write(net_fd, &packet, OFFSETOF(teavpn_packet, data));

	nread = read(net_fd, &packet, sizeof(packet));
	if (packet.info.type == TEAVPN_PACKET_CONF) {
		#ifdef TEAVPN_DEBUG
		printf("inet4: \"%s\"\n", packet.data.conf.inet4);
		printf("inet4_bc: \"%s\"\n", packet.data.conf.inet4_broadcast);
		fflush(stdout);
		#endif

		seq++; // Must be 4
		if (packet.info.seq != seq) {
			printf("Invalid seq number (server_seq: %ld) (client_seq: %ld)\n", packet.info.seq, seq);
			goto close;
		}

	} else {
		printf("Invalid packet\n");
		fflush(stdout);
		goto close;
	}

	if (!teavpn_client_init_iface(config, &(packet.data.conf))) {
		printf("Cannot init interface\n");
		close(tap_fd);
		return 1;
	}

	packet.info.type = TEAVPN_PACKET_DATA;
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
			nread = read(tap_fd, &(packet.data.data), TEAVPN_TAP_READ_SIZE);
			if (nread < 0) {
				perror("Error read from tap_fd");
				goto next_1;
			}

			packet.info.seq = ++seq;
			packet.info.len = OFFSETOF(teavpn_packet, data) + nread;
			nwrite = write(net_fd, &packet, OFFSETOF(teavpn_packet, data) + nread);
			debug_log(3, "[%ld] Write to server %ld bytes\n", packet.info.seq, nwrite);

			if (nwrite < 0) {
				seq--;
				perror("Error write to net_fd");
				goto next_1;
			}
		}

		next_1:
		if (FD_ISSET(net_fd, &rd_set)) {
			nread = read(net_fd, &packet, sizeof(packet));

			if (nread < 0) {
				perror("Error read from net_fd");
				goto next_1;	
			}

			if (packet.info.type == TEAVPN_PACKET_DATA) {

				seq++;
				debug_log(3, "[%ld][%ld] Read from server %ld bytes (pkt_len: %ld) (%s)\n",
					seq, packet.info.seq, nread, packet.info.len,
					(seq == packet.info.seq) ? "match" : "invalid seq");

				// Deep debugging here.
				// This is the unforgetable history of my experience.
				//
				// There was something wrong with packet length and sequence number
				// it took me severals hour to fix.
				//
				if (packet.info.len != nread) {
					// Do hexdump!
					for (uint16_t i = 0; i < nread; ++i) {
						printf("%#x ", ((unsigned char *)(&packet))[i]);
						if ((i % 16) == 0) printf("\n");
					}
					printf("\n");
					fflush(stdout);
				}


				nwrite = write(tap_fd, packet.data.data, packet.info.len - OFFSETOF(teavpn_packet, data));
				if (nwrite < 0) {
					perror("Error write to tap_fd");
					continue;
				}
			}
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
		// ret = false;
		// goto ret;
	} else {
		while ((*p) != ' ') p++;
		p++;
		q = p;
		while ((*q) != ' ') q++;
		*q = '\0';
	}


	// sprintf(cmd, "/sbin/ip route add %s/32 via %s", config->server_ip, p);
	// debug_log(1, "Executing: %s\n", cmd);
	// system(cmd);

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
