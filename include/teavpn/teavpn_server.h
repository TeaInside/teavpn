
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_server_h
#define __teavpn__teavpn_server_h

#include <stdio.h>
#include <arpa/inet.h>

#include <teavpn/teavpn.h>
#include <teavpn/teavpn_handshake.h>

#define BUFCHAN_ALLOC 24

uint8_t teavpn_udp_server(server_config *config);
uint8_t teavpn_tcp_server(server_config *config);

struct buffer_channel {	
	ssize_t length;
	uint16_t ref_count;
	char buffer[sizeof(teavpn_packet)];
};

#define BUFPTR(X, Y) ((Y)&(X.buffer[0]))
#define BUFPPTR(X, Y) ((Y)&(X->buffer[0]))

#endif
