
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_h
#define __teavpn__teavpn_h

#include <stdint.h>
#include <arpa/inet.h>

typedef struct _server_config {
	char *bind_addr;
	char *config_file;
	char *error_log_file;
	char *data_dir;

	// Interface information
	char *dev;
	char *inet4;
	char *inet4_broadcast;
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
	uint16_t mtu;
	// End interface information

	// Credential information
	char *username;
	char *password;
	uint8_t username_len;
	uint8_t password_len;
	// End credential information

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

struct teavpn_client_ip {
	char inet4[sizeof("xxx.xxx.xxx.xxx/xx")];
	char inet4_broadcast[sizeof("xxx.xxx.xxx.xxx")];
	char inet4_route[sizeof("xxx.xxx.xxx.xxx")];
};

#define TEAVPN_PACKET_BUFFER 5000

/**
 * TeaVPN Packet.
 */
enum teavpn_packet_type {
	TEAVPN_PACKET_AUTH = (1 << 0),
	TEAVPN_PACKET_ACK = (1 << 1),
	TEAVPN_PACKET_RST = (1 << 2),
	TEAVPN_PACKET_DATA = (1 << 3)
};

struct teavpn_packet_auth {
	uint8_t username_len;
	uint8_t password_len;
	char username[64];
	char password[255];
};

struct packet_info {
	enum teavpn_packet_type type;
	uint16_t len;
	uint64_t seq;
};

struct teavpn_packet {
	struct packet_info info;
	char data[TEAVPN_PACKET_BUFFER];
};

#define TEAVPN_PACKET_BUFFER_CONTAINER_SIZE (sizeof(struct teavpn_packet))

int tun_alloc(char *dev, int flags);
void debug_log(uint8_t vlevel, const char *msg, ...);

#endif
