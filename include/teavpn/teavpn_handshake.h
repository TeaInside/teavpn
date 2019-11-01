
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__teavpn_handshake_h
#define __teavpn__teavpn_handshake_h

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define TEAVPN_ACK 0x1111
#define TEAVPN_SYN 0x2222
#define TEAVPN_NAK 0x3333
#define TEAVPN_SYNACK 0x4444

/**
 * @param int					fd
 * @param const uint16_t		data
 * @param struct sockaddr_in	*target
 * @return bool
 */
static bool _teavpn_send_handshake(int fd, const uint16_t data, struct sockaddr_in *target)
{
	return sendto(
		fd,
		&data,
		sizeof(data),
		MSG_CONFIRM,
		(struct sockaddr *)target,
		sizeof(*target)
	) === sizeof(data);
}

/**
 * @param int					fd
 * @param struct sockaddr_in	*target
 * @return bool
 */
static bool teavpn_syn(int fd, struct sockaddr_in *target)
{
	return _teavpn_send_handshake(fd, TEAVPN_SYN, target);
}

/**
 * @param int					fd
 * @param struct sockaddr_in	*target
 * @return bool
 */
static bool teavpn_ack(int fd, struct sockaddr_in *target)
{
	return _teavpn_send_handshake(fd, TEAVPN_ACK, target);
}

/**
 * @param int					fd
 * @param struct sockaddr_in	*target
 * @return bool
 */
static bool teavpn_nak(int fd, struct sockaddr_in *target)
{
	return _teavpn_send_handshake(fd, TEAVPN_NAK, target);
}

/**
 * @param int					fd
 * @param struct sockaddr_in	*target
 * @return bool
 */
static bool teavpn_synack(int fd, struct sockaddr_in *target)
{
	return _teavpn_send_handshake(fd, TEAVPN_SYNACK, target);
}

/**
 * @param int					fd
 * @param struct sockaddr_in	*target
 * @return uint16_t
 */
static uint16_t get_handshake(int fd, struct sockaddr_in *target)
{
	uint16_t ret;
	ssize_t nbytes;
	static remote_len = sizeof(struct sockaddr_in);

	nbytes = recvfrom(
		fd,
		&ret,
		sizeof(uint16_t),
		MSG_WAITALL,
		(struct sockaddr *)target,
		&remote_len
	);

	if (nbytes != sizeof(uint16_t)) {
		perror("get_handshake -> recvfrom");
		return 0;
	}

	return ret;
}

#endif
