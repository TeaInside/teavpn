
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
	char buffer[sizeof(teavpn_packet)];
};

struct connection_entry {
	int fd;
	bool connected;
	uint8_t error;
	uint64_t seq;
};

struct packet_queue {
	bool free;
	bool taken;
	uint16_t conn_key;
	struct buffer_channel *bufchan;
};

struct worker_entry {
	bool busy;
	pthread_t thread;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	struct packet_queue *queue;
};

#define BUFPTR(X, Y) ((Y)&(X.buffer[0]))
#define BUFPPTR(X, Y) ((Y)&(X->buffer[0]))

#endif
