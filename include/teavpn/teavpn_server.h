
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_server_h
#define __teavpn__teavpn_server_h

#include <arpa/inet.h>

#include <teavpn/teavpn.h>

uint8_t teavpn_server(server_config *config);

typedef struct client_state_ {
	int fd;
	struct sockaddr_in addr;
} client_state;

#endif
