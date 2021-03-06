
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn/teavpn.h>

uint8_t verbose_level = 0;

uint8_t __internal_debug_log(const char *msg, ...)
{
	va_list argp;
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char *time = asctime(timeinfo);
	time[24] = '\0';

	va_start(argp, msg);
	fprintf(stdout, "[%s]: ", time);
	vfprintf(stdout, msg, argp);
	fprintf(stdout, "\n");
	va_end(argp);
	fflush(stdout);
	return 0;
}


/**
 * @param char	*dev
 * @param int	flat
 * @return int
 */
int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
#pragma GCC diagnostic pop
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

