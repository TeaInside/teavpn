
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <string.h>
#include <teavpn/teavpn.h>
#include <teavpn/helpers.h>
#include <teavpn/teavpn_server.h>

FILE *teavpn_auth_check(server_config *config, struct teavpn_packet_auth *auth)
{
	size_t len;
	FILE *h1 = NULL, *h2 = NULL;
	char file[512], buffer[255];

	sprintf(file, "%s/users/%s/password", config->data_dir, auth->username);
	printf("%s\n", file);
	fflush(stdout);

	h1 = fopen(file, "r");
	if (h1 == NULL) {
		return NULL;
	}

	if (fgets(buffer, 254, h1)) {
		len = strlen(buffer);

		if (buffer[len - 1] == '\n') {
			buffer[len - 1] = '\0';
		}

		printf("rpassword: \"%s\"\n", buffer);
		printf("auth_pas: \"%s\"\n", auth->password);

		if (!strcmp(auth->password, buffer)) {
			sprintf(file, "%s/users/%s/ip", config->data_dir, auth->username);
			h2 = fopen(file, "r");
		}
	}

	fclose(h1);
	return h2;
}
