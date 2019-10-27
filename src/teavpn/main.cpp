
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <teavpn/teavpn.h>
#include <teavpn/cli_arg.h>
#include <teavpn/teavpn_server.h>
#include <teavpn/teavpn_client.h>

int main(int argc, char **argv, char **envp)
{
	uint8_t exit_code;
	teavpn_config config;

	if (!argv_parser(&config, argc, argv, envp)) {
		exit_code = 1;
		goto ret;
	}

	switch (config.type) {
		case teavpn_server_config:
			exit_code = teavpn_server(&(config.config.server));
			break;
		case teavpn_client_config:
			exit_code = teavpn_client(&(config.config.client));
			break;
		default:
			printf("Invalid config type\n");
			exit_code = 1;
			break;
	}

	ret:
	return exit_code;
}
