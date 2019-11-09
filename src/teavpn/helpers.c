
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <teavpn/helpers.h>

char *escapeshellarg(char *str)
{
	size_t x, y = 0;
	size_t l = strlen(str);
	char *cmd;

	cmd = (char *)malloc(sizeof(char) * l * 4); // Worst case

#ifdef PHP_WIN32
	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif

	for (x = 0; x < l; x++) {
		switch (str[x]) {
#ifdef PHP_WIN32
		case '"':
		case '%':
		case '!':
			cmd[y++] = ' ';
			break;
#else
		case '\'':
			cmd[y++] = '\'';
			cmd[y++] = '\\';
			cmd[y++] = '\'';
#endif
		/* fall-through */
		default:
			cmd[y++] = str[x];
		}
	}
#ifdef PHP_WIN32
	if (y > 0 && '\\' == cmd[y - 1]) {
		int k = 0, n = y - 1;
		for (; n >= 0 && '\\' == cmd[n]; n--, k++);
		if (k % 2) {
			cmd[y++] = '\\';
		}
	}

	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif
	cmd[y] = '\0';

	return cmd;
}

/**
 * @param const char *read
 * @return uint32_t
 */
uint32_t ip_read_conv(const char *read)
{
	uint32_t ret = 0;
	uint8_t bufptr = 0, i = 0;
	char buf[4] = "\0\0\0";

	while (((*read) != '\0') && ((*read) != '/')) {
		buf[bufptr] = *read;
		read++;
		bufptr++;
		if ((bufptr == 3) || ((*read) == '.')) {
			bufptr = 0;
			ret |= atoi(buf) << i;
			i += 8;
			read++; // skip dot
		}
	}

	if (i < 32) {
		ret |= atoi(buf) << i;
	}

	return ret;
}
