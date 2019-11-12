
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

static void print_err_sig(uint8_t sig);
static bool teavpn_tcp_client_init(char *config_buffer, client_config *config);

/**
 * Main point of TeaVPN TCP Client.
 */
__attribute__((force_align_arg_pointer)) uint8_t teavpn_tcp_client(client_config *config)
{
	fd_set rd_set;
	uint64_t seq = 0;
	int fd_ret, max_fd;
	teavpn_packet packet;
	register ssize_t nwrite, nread;

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
	 * Use packet buffer as struct sockadd_in.
	 */
	#define server_addr ((struct sockaddr_in *)&(packet.data.data))


	if (teavpn_tcp_client_init(config_buffer, config)) {
		return 1;
	}


	/**
	 * Prepare server address.
	 */
	memset(server_addr, 0, sizeof(struct sockaddr_in));
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(config->server_port);
	server_addr->sin_addr.s_addr = inet_addr(config->server_ip);



	/**
	 * Conncet to TeaVPN server.
	 */
	debug_log(0, "Connecting to %s:%d...\n", config->server_ip, config->server_port);
	if (connect(net_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) < 0) {
		debug_log(0, "Error on connect");
		perror("Error on connect");
		goto close;
	}


	/**
	 * Prepare auth packet.
	 */
	packet.info.type = TEAVPN_PACKET_AUTH;
	packet.info.len = OFFSETOF(teavpn_packet, data) + sizeof(struct teavpn_packet_auth);
	packet.data.auth.username_len = config->username_len;
	packet.data.auth.password_len = config->password_len;
	strcpy(packet.data.auth.username, config->username);
	strcpy(packet.data.auth.password, config->password);

	/**
	 * Debug only.
	 */
	#ifdef TEAVPN_DEBUG
	debug_log(3, "username: \"%s\"\n", packet.data.auth.username);
	debug_log(3, "password: \"%s\"\n", packet.data.auth.password);
	debug_log(3, "username_len: %d\n", packet.data.auth.username_len);
	debug_log(3, "password_len: %d\n", packet.data.auth.password_len);
	#endif

	/**
	 * Send auth packet to server.
	 */
	packet.info.seq = ++seq; // seq 1
	nwrite = write(net_fd, &packet, TEAVPN_PACK(sizeof(packet.data.auth)));

	debug_log(3, "[%ld] Write auth packet to server %ld bytes", seq, nwrite);

	if (nwrite == 0) {
		debug_log(0, "Connection reset by peer");
		goto close;
	}

	if (nwrite < 0) {
		debug_log(0, "Error write to net_fd");
		perror("Error write to net_fd");
		goto close;
	}



	/**
	 * Read server response.
	 */
	seq++; // seq 2
	nread = read(net_fd, &packet, sizeof(packet));

	debug_log(
		3,
		"[%ld] Read server signal %ld bytes (client_seq: %ld) (server_seq: %ld) %s",
		seq, nread, seq, packet.info.seq, (seq == packet.info.seq) ? "match" : "invalid"
	);

	if (seq != packet.info.seq) {
		debug_log(0, "Invalid packet sequence (client_seq: %ld) (server_seq: %ld)",
			seq, packet.info.seq);
		goto close;
	}

	/**
	 * Check server response.
	 */
	if (packet.info.type == TEAVPN_PACKET_SIG) {
		if (packet.data.sig.sig == TEAVPN_SIG_AUTH_OK) {
			debug_log(0, "Auth OK");
		} else {
			print_err_sig(packet.data.sig.sig);
			goto close;
		}
	} else {
		debug_log(0, "Invalid server response");
		goto close;
	}



	/**
	 * Send ack packet to server.
	 */
	packet.info.type = TEAVPN_PACKET_ACK;
	packet.info.seq = ++seq; // seq 3
	nwrite = write(net_fd, &packet, TEAVPN_PACK(0));

	debug_log(3, "[%ld] Write ack packet to server %ld bytes", seq, nwrite);

	if (nwrite == 0) {
		debug_log(0, "Connection reset by peer");
		goto close;
	}

	if (nwrite < 0) {
		debug_log(0, "Error write to net_fd");
		perror("Error write to net_fd");
		goto close;
	}



	/**
	 * Read network interface configuration.
	 */
	seq++; // seq 4
	nread = read(net_fd, &packet, sizeof(packet));

	if (seq != packet.info.seq) {
		debug_log(0, "Invalid packet sequence (client_seq: %ld) (server_seq: %ld)",
			seq, packet.info.seq);
		goto close;
	}

	if (packet.info.type != TEAVPN_PACKET_CONF) {
		debug_log(0, "Invalid packet");
		goto close;
	}

	/**
	 * Debug only.
	 */
	#ifdef TEAVPN_DEBUG
	debug_log(3, "inet4: \"%s\"\n", packet.data.conf.inet4);
	debug_log(3, "inet4_bc: \"%s\"\n", packet.data.conf.inet4_broadcast);
	#endif



	/**
	 * Apply network interface configuration to TUN/TAP interface.
	 */
	if (!teavpn_client_init_iface(config, &(packet.data.conf))) {
		debug_log(0, "Cannot init TUN/TAP interface\n");
		goto close;
	}



	/**
	 * Calculate maximum value between tap_fd and net_fd.
	 */
	max_fd = (tap_fd > net_fd) ? tap_fd : net_fd;

	packet.info.type = TEAVPN_PACKET_DATA;

	/**
	 * TeaVPN client event loop.
	 */
	while (true) {
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
		 * Read data from client TUN/TAP and write it to server fd.
		 */
		if (FD_ISSET(tap_fd, &rd_set)) {
			/**
			 * Read from TUN/TAP.
			 */
			nread = read(tap_fd, &(packet.data.data), TEAVPN_TAP_READ_SIZE);
			debug_log(4, "Read from tap_fd %ld bytes", nread);
			if (nread < 0) {
				debug_log(0, "Error read from tap_fd");
				perror("Error read from tap_fd");
				goto next_1;
			}

			/**
			 * Write to server fd.
			 */
			packet.info.seq = ++seq;
			packet.info.len = TEAVPN_PACK(nread);
			nwrite = write(net_fd, &packet, TEAVPN_PACK(nread));
			debug_log(3, "[%ld] Write data to server %ld bytes", seq, nwrite);
			if (nwrite == 0) {
				debug_log(0, "Connection reset by peer");
				goto close;
			}
			if (nwrite < 0) {
				debug_log(0, "Error write to net_fd");
				perror("Error write to net_fd");
				goto next_1;
			}
		}


		next_1:
		/**
		 * Read data from server and write it to TUN/TAP interface.
		 */
		if (FD_ISSET(net_fd, &rd_set)) {
			/**
			 * Read from server fd.
			 */
			seq++;
			nread = read(net_fd, &packet, sizeof(packet));
			debug_log(3, "[%ld] Read data from server %ld bytes (client_seq: %ld) (server_seq: %ld) %s",
				seq, nread, seq, packet.info.seq, (seq == packet.info.seq) ? "match" : "invalid");
			if (nread == 0) {
				debug_log(0, "Connection reset by peer");
				goto close;
			}
			if (nread < 0) {
				debug_log(0, "Error read from net_fd");
				perror("Error read from net_fd");
				goto next_2;
			}

			/**
			 * Write to TUN/TAP.
			 */
			nwrite = write(tap_fd, &(packet.data.data), nread - OFFSETOF(teavpn_packet, data));
			debug_log(4, "Write to tap_fd %ld bytes", nwrite);
			if (nread < 0) {
				debug_log(0, "Error read from tap_fd");
				perror("Error read from tap_fd");
				goto next_2;
			}
		}

		next_2:
		(void)1;
	}

close:
	close(tap_fd);
	close(net_fd);

	return 1;

	#undef server_addr
}


/**
 * Initialize TeaVPN client (socket, auth, etc.)
 */
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


	/**
	 * Create TUN/TAP interface.
	 */
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully created a new interface \"%s\".\n", config->dev);


	/**
	 * Create TCP socket.
	 */
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
 * Print signal error message.
 */
static void print_err_sig(uint8_t sig)
{
	switch (sig) {
		case TEAVPN_SIG_AUTH_REJECT:
			debug_log(0, "Invalid username or password");
			break;
		case TEAVPN_SIG_UNKNOWN:
			debug_log(0, "Invalid error (code: TEAVPN_SIG_AUTH_UNKNOWN)");
			break;
		case TEAVPN_SIG_DROP:
			debug_log(0, "Connection dropped!");
			break;
		case TEAVPN_SIG_AUTH_OK:
			debug_log(0, "Success");
			break;
		default:
			debug_log(0, "Unknown signal");
			break;
	}
}
