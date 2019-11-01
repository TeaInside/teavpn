
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_server_h
#define __teavpn__teavpn_server_h

#include <arpa/inet.h>

#include <teavpn/teavpn.h>
#include <teavpn/teavpn_handshake.h>

#define BUFFER_CHANNEL_SIZE (UDP_BUFFER + 1)

uint8_t teavpn_udp_server(server_config *config);
uint8_t teavpn_tcp_server(server_config *config);

struct connection_entry {
	bool connected;
	uint64_t send_counter;
	uint64_t recv_counter;
	struct sockaddr_in info;
};

struct buffer_channel {	
	ssize_t length;
	uint16_t ref_count;
	char *bufptr;
	char buffer[BUFFER_CHANNEL_SIZE];
};

#endif
