
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_h
#define __teavpn__teavpn_h

#include <stdint.h>

typedef struct _server_config {
	char *bind_addr;
	char *config_file;
	char *error_log_file;

	// Interface information
	char *dev;
	char *inet4;
	uint16_t mtu;
	// End interface information

	uint16_t bind_port;
	uint8_t verbose_level;
	uint8_t threads;
} server_config;

typedef struct _client_config {
	char *server_ip;
	char *config_file;
	char *error_log_file;

	// Interface information
	char *dev;
	char *inet4;
	uint16_t mtu;
	// End interface information

	uint16_t server_port;
	uint8_t verbose_level;
	uint8_t threads;
} client_config;

enum _config_type {
	teavpn_server_config = 0,
	teavpn_client_config = 1
};

union _config {
	server_config server;
	client_config client;
};

typedef struct _teavpn_config {
	union _config config;
	enum _config_type type;
} teavpn_config;

int tun_alloc(char *dev, int flags);
void debug_log(uint8_t vlevel, const char *msg, ...);

#endif
