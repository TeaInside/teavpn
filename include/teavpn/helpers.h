
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__helpers_h
#define __teavpn__helpers_h

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

char *escapeshellarg(char *str);
uint32_t ip_read_conv(const char *read);

#endif
