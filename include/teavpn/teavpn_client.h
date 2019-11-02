
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_client_h
#define __teavpn__teavpn_client_h

#include <arpa/inet.h>

#include <teavpn/teavpn.h>
#include <teavpn/teavpn_handshake.h>

uint8_t teavpn_udp_client(client_config *config);
uint8_t teavpn_tcp_client(client_config *config);

#endif
