
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_server_h
#define __teavpn__teavpn_server_h

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <teavpn/teavpn.h>
#include <teavpn/teavpn_handshake.h>

// Buffer channel amount
#define BUFCHAN_ALLOC 24

// Max connections
#define CONNECTION_ALLOC 24

// Queue amount.
#define QUEUE_AMOUNT 24

uint8_t teavpn_udp_server(server_config *config);
uint8_t teavpn_tcp_server(server_config *config);

struct buffer_channel {
	uint16_t ref_count;
	ssize_t len;
	char buffer[sizeof(teavpn_packet)];
};

struct connection_entry {
	int fd;
	bool connected;
	uint8_t error;
	uint64_t seq;
	uint32_t priv_ip;
	struct sockaddr_in addr;
};

FILE *teavpn_auth_check(server_config *config, struct teavpn_packet_auth *auth);

#endif
