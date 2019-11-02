
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
static uint16_t entry_count = 0;
static struct buffer_channel *bufchan;
static struct connection_entry *entries;

static int16_t get_buffer_channel_index();
static void *teavpn_accept_connection(void *);
static void *teavpn_thread_worker(uint64_t entry);
static bool teavpn_server_socket_setup(int sock_fd);
static void teavpn_server_init_iface(server_config *config);

/**
 * @param server_config *config
 * @return uint8_t
 */
uint8_t teavpn_tcp_server(server_config *config)
{
	fd_set rd_set;
	ssize_t nwrite;
	int fd_ret, max_fd;
	int16_t bufchan_index;
	threadpool threads_pool;
	pthread_t accept_worker;
	char config_buffer[4096];
	struct teavpn_packet *packet;
	struct sockaddr_in server_addr;
	uint64_t tap2net = 0, net2tap = 0;
	struct connection_entry _entries[MAX_CLIENT_ENTRY];
	struct buffer_channel _bufchan[BUFFER_CHANNEL_ENTRY];

	entries = _entries;
	bufchan = _bufchan;

	for (uint8_t i = 0; i < MAX_CLIENT_ENTRY; i++) {
		entries[i].error = 0;
		entries[i].connected = false;
	}

	for (uint8_t i = 0; i < BUFFER_CHANNEL_ENTRY; i++) {
		memset(&(bufchan[i]), 0, sizeof(struct buffer_channel));
		bufchan[i].bufptr = bufchan[i].buffer;
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

	// Create TUN/TAP interface.
	debug_log(2, "Allocating TUN/TAP interface...");
	if ((tap_fd = tun_alloc(config->dev, IFF_TUN)) < 0) {
		printf("Error connecting to TUN/TAP interface %s!\n", config->dev);
		return 1;
	}
	debug_log(2, "OK\n");
	debug_log(0, "Successfully created a new interface \"%s\".\n", config->dev);

	// Initialize TUN/TAP interface.
	teavpn_server_init_iface(config);

	// Create TCP socket.
	debug_log(1, "Creating TCP socket...\n");
	if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation failed");
		return 1;
	}
	debug_log(1, "TCP socket created successfully\n");

	// Setting up socket.
	debug_log(1, "Setting up socket file descriptor...\n");
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

	// Listen
	if (listen(net_fd, 3) < 0) {
		perror("Listen failed");
		return 1;
	}

	debug_log(0, "Listening on %s:%d...\n", config->bind_addr, config->bind_port);

	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	// Run accept worker.
	pthread_create(&accept_worker, NULL, teavpn_accept_connection, (void *)config);

	while (true) {

		max_fd = tap_fd;
		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);

		for (uint16_t i = 0; i < entry_count; i++) {
			if (entries[i].connected) {
				if (entries[i].fd > max_fd) {
					max_fd = entries[i].fd;
				}
				FD_SET(entries[i].fd, &rd_set);
			}
		}

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

		// Read from server's tap_fd.
		if (FD_ISSET(tap_fd, &rd_set)) {
			tap2net++;
			packet = (struct teavpn_packet *)bufchan[bufchan_index].buffer;
			packet->info.type = TEAVPN_PACKET_DATA;
			bufchan[bufchan_index].ref_count = 0;
			bufchan[bufchan_index].length = read(tap_fd, packet->data, sizeof(packet->data));

			if (bufchan[bufchan_index].length < 0) {
				perror("Error read tap_fd");
				goto next;
			}

			debug_log(3, "read from tap_fd %ld bytes\n", bufchan[bufchan_index].length);
			bufchan[bufchan_index].length += sizeof(packet->info);

			for (uint16_t i = 0; i < entry_count; i++) {
				if (entries[i].connected) {
					bufchan[bufchan_index].ref_count++;
					thpool_add_work(
						threads_pool,
						(void * (*)(void *))teavpn_thread_worker,
						(void *)((uint64_t) (i | (bufchan_index << 16)))
					);
				}
			}
		}

		// Read from client's fd.
		next:
		for (uint16_t i = 0; i < entry_count; i++) {
			if (FD_ISSET(entries[i].fd, &rd_set)) {
				if (entries[i].connected) {
					do {
						bufchan_index = get_buffer_channel_index();
					} while (bufchan_index == -1);

					packet = (struct teavpn_packet *)bufchan[bufchan_index].buffer;
					packet->info.type = TEAVPN_PACKET_DATA;
					bufchan[bufchan_index].ref_count = 0;
					bufchan[bufchan_index].length = read(entries[i].fd, packet, sizeof(*packet));
					if (bufchan[bufchan_index].length < 0) {
						entries[i].error++;
						if (entries[i].error > 5) {
							entries[i].connected = false;
							close(entries[i].fd);
						}
						perror("read from client fd");
						goto next_2;
					}

					nwrite = write(tap_fd, packet->data, bufchan[bufchan_index].length - sizeof(packet->info));
					if (nwrite < 0) {
						perror("write to tap_fd");
						goto next_2;
					}

					debug_log(3, "write to tap_fd %ld bytes\n", nwrite);

					for (uint16_t j = 0; j < entry_count; j++) {
						if (entries[j].connected && (j != i)) {
							bufchan[bufchan_index].ref_count++;
							thpool_add_work(
								threads_pool,
								(void * (*)(void *))teavpn_thread_worker,
								(void *)((uint64_t) (j | (bufchan_index << 16)))
							);
						}
					}
				}
			}
		}

		next_2:
		(void)0;
	}
}

/**
 * @param uint64_t entry
 * @return void *
 */
static void *teavpn_thread_worker(uint64_t entry)
{
	ssize_t nwrite;
	uint16_t
		bufchan_index = (entry >> 16) & 0xffff,
		entry_index = entry & 0xffff;

	entries[entry_index].send_counter++;
	nwrite = write(entries[entry_index].fd, bufchan[bufchan_index].buffer, bufchan[bufchan_index].length);
	if (nwrite < 0) {
		entries[entry_index].error++;
		perror("Error write to client");
		if (entries[entry_index].error > 5) {
			entries[entry_index].connected = false;
			close(entries[entry_index].fd);
		}
	}

	printf("write bytes: %ld\n", nwrite);
	printf("bufchan_index: %d\n", bufchan_index);
	printf("entry_index: %d\n", entry_index);
	fflush(stdout);

	bufchan[bufchan_index].ref_count--;
}

/**
 * @param void *ptr
 * @return void *
 */
static void *teavpn_accept_connection(void *ptr)
{
	int client_fd;
	ssize_t nwrite, nread;
	struct teavpn_packet packet;
	#define config ((server_config *)ptr)
	#define auth ((struct teavpn_packet_auth *)(packet.data))	
	#define client_ip ((struct teavpn_client_ip *)&(packet.data))
	#define client_addr ((struct sockaddr_in *)(&(packet.data[sizeof(struct teavpn_packet_auth)])))

	static socklen_t rlen = sizeof(struct sockaddr_in);

	debug_log(1, "Accepting connection...\n");

	while (true) {

		client_fd = accept(net_fd, (struct sockaddr *)client_addr, &rlen);

		if (client_fd < 0) {
			perror("Error accept (accept worker)");
			continue;
		}

		nread = read(client_fd, &packet, sizeof(struct teavpn_packet));
		if (nread < 0) {
			perror("Error read (accept worker)");
			continue;
		}

		if (packet.info.type == TEAVPN_PACKET_AUTH) {
			debug_log(
				1,
				"A new client is connecting %s:%d\n",
				inet_ntoa(client_addr->sin_addr),
				ntohs(client_addr->sin_port)
			);

			#ifdef TEAVPN_DEBUG
			printf("Username length: %d\n", auth->username_len);
			printf("Password length: %d\n", auth->password_len);
			printf("Username: \"%s\"\n", auth->username);
			printf("Password: \"%s\"\n", auth->password);
			fflush(stdout);
			#endif

			FILE *h = teavpn_auth_check(config, auth);
			if (h != NULL) {
				char buffer[64];
				size_t len, sp = 0;

				memset(buffer, 0, sizeof(buffer));
				fgets(buffer, 63, h);
				len = strlen(buffer);

				while ((buffer[sp] != ' ')) {
					if (sp >= len) {
						fclose(h);
						close(client_fd);
						debug_log(1, "Invalid ip configuration for username %s", auth->username);
						goto next;
					}
					sp++;
				}

				if (sp > sizeof("xxx.xxx.xxx.xxx/xx")) {
					fclose(h);
					close(client_fd);
					debug_log(1, "Invalid ip configuration for username %s", auth->username);
					goto next;
				}

				if ((len - (sp - 1)) > sizeof("xxx.xxx.xxx.xxx")) {
					fclose(h);
					close(client_fd);
					debug_log(1, "Invalid ip configuration for username %s", auth->username);
					goto next;	
				}

				debug_log(
					1,
					"%s connected from (%s:%d) [%s]\n",
					auth->username,
					inet_ntoa(client_addr->sin_addr),
					ntohs(client_addr->sin_port),
					buffer
				);

				entries[entry_count].fd = client_fd;
				entries[entry_count].priv_ip = ip_read_conv(buffer);
				entries[entry_count].send_counter = 0;
				entries[entry_count].recv_counter = 0;
				entries[entry_count].info = *client_addr;

				#ifdef TEAVPN_DEBUG
				printf("IP conv: %#x\n", entries[entry_count].priv_ip);
				fflush(stdout);
				#endif

				fclose(h);

				memcpy(client_ip->inet4, buffer, sp);
				client_ip->inet4[sp] = '\0';
				strcpy(client_ip->inet4_broadcast, &(buffer[sp+1]));

				#ifdef TEAVPN_DEBUG
				printf("inet4: \"%s\"\n", client_ip->inet4);
				printf("inet4_bc: \"%s\"\n", client_ip->inet4_broadcast);
				fflush(stdout);
				#endif

				packet.info.type = TEAVPN_PACKET_ACK;
				nwrite = write(client_fd, &packet, sizeof(packet.info) + sizeof(*client_ip));
				if (nwrite < 0) {
					perror("Error write (accept_worker)");
					close(client_fd);
					goto next;
				}

				entries[entry_count].connected = true;
				entry_count++;
			} else {
				packet.info.type = TEAVPN_PACKET_RST;
				nwrite = write(client_fd, &packet, sizeof(packet.info));
				if (nwrite < 0) {
					perror("Error write (accept_worker)");
				}
				close(client_fd);
			}
		} else {
			close(client_fd);
		}

		next:
		(void)0;
	}

	#undef auth
	#undef config
	#undef client_ip
	#undef client_addr
}

/**
 * @return int16_t
 */
static int16_t get_buffer_channel_index()
{
	static bool sleep_state = false;
	static uint8_t buf_chan_state = 0;

	for (int16_t i = 0; i < BUFFER_CHANNEL_ENTRY; ++i) {
		if (bufchan[i].ref_count == 0) {
			return i;
		}
	}

	if (buf_chan_state > 5) {
		sleep_state = true;
	} else {
		buf_chan_state++;
	}

	if (sleep_state) {
		sleep(1);
		buf_chan_state--;
		if (buf_chan_state <= 2) {
			sleep_state = false;
		}
	}

	// Buffer channels are all busy.
	return -1;
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
static void teavpn_server_init_iface(server_config *config)
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
