
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <teavpn/teavpn_server.h>
#include <teavpn/teavpn_config_parser.h>

bool teavpn_server_config_parser(char *internal_buf, server_config *config)
{
	uint16_t line = 1;
	char buffer[4096];
	bool ret = true, sp;
	size_t i, j, k, l, len;

	FILE *h = fopen(config->config_file, "r");

	if (h == NULL) {
		printf("Cannot open config file: %s\n", config->config_file);
		return false;
	}

	while (fgets(buffer, 4095, h)) {

		len = strlen(buffer);
		if (buffer[len - 1] != '\n') {
			buffer[len] = '\n';
			buffer[len + 1] = '\0';
		}
		i = j = k = l = 0;

		// ltrim key
		while ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\r')) i++;
		j = i;

		if ((buffer[i] == '#') || (buffer[i] == '\n')) continue;

		while (buffer[i] != '=') {
			if (buffer[i] == '\n') {
				printf("Parse error on line %d: couldn't find equal separator\n", line);
				ret = false;
				goto ret;
			}
			i++;
		}
		buffer[i] = '\0';
		k = i + 1;
		i--;

		sp = false;
		// rtrim key
		while ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\r')) {
			i--;
			sp = true;
		}

		if (sp) buffer[i + 1] = '\0';

		// ltrim value
		while ((buffer[k] == ' ') || (buffer[k] == '\t') || (buffer[k] == '\r')) k++;

		l = k;

		if (buffer[k] == '\n') {
			buffer[k] = '\0';
		} else {
			while (buffer[l] != '\n') {
				if (buffer[l] == '#') {
					len = l + 1;
					buffer[l] = '\n';
					break;
				}
				l++;
			}
			buffer[l] = '\0';
			l--;

			sp = false;
			// rtrim key
			while ((buffer[l] == ' ') || (buffer[l] == '\t') || (buffer[l] == '\r')) {
				l--;
				sp = true;
			}
			if (sp) buffer[l + 1] = '\0';
		}

		// printf("\"%s\" = \"%s\"\n", &(buffer[j]), &(buffer[k]));
		if (!strcmp(&(buffer[j]), "dev")) {
			strcpy(internal_buf, &(buffer[k]));
			config->dev = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else if (!strcmp(&(buffer[j]), "mtu")) {
			config->mtu = (uint16_t)atoi(&(buffer[k]));
		} else if (!strcmp(&(buffer[j]), "inet4")) {
			strcpy(internal_buf, &(buffer[k]));
			config->inet4 = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else if (!strcmp(&(buffer[j]), "bind_addr")) {
			strcpy(internal_buf, &(buffer[k]));
			config->bind_addr = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else if (!strcmp(&(buffer[j]), "bind_port")) {
			config->bind_port = (uint16_t)atoi(&(buffer[k]));
		} else if (!strcmp(&(buffer[j]), "threads")) {
			config->threads = (uint8_t)atoi(&(buffer[k]));
		} else if (!strcmp(&(buffer[j]), "data_dir")) {
			strcpy(internal_buf, &(buffer[k]));
			config->data_dir = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else {
			printf("Invalid config key \"%s\" on line %d\n", &(buffer[j]), line);
		}

		line++;
	}


	ret:
	fclose(h);

	return ret;
}


bool teavpn_client_config_parser(char *internal_buf, client_config *config)
{
	uint16_t line = 1;
	char buffer[4096];
	bool ret = true, sp;
	size_t i, j, k, l, len;

	FILE *h = fopen(config->config_file, "r");

	if (h == NULL) {
		printf("Cannot open config file: %s\n", config->config_file);
		return false;
	}

	while (fgets(buffer, 4095, h)) {

		len = strlen(buffer);
		if (buffer[len - 1] != '\n') {
			buffer[len] = '\n';
			buffer[len + 1] = '\0';
		}
		i = j = k = l = 0;

		// ltrim key
		while ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\r')) i++;
		j = i;

		if ((buffer[i] == '#') || (buffer[i] == '\n')) continue;

		while (buffer[i] != '=') {
			if (buffer[i] == '\n') {
				printf("Parse error on line %d: couldn't find equal separator\n", line);
				ret = false;
				goto ret;
			}
			i++;
		}
		buffer[i] = '\0';
		k = i + 1;
		i--;

		sp = false;
		// rtrim key
		while ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\r')) {
			i--;
			sp = true;
		}

		if (sp) buffer[i + 1] = '\0';

		// ltrim value
		while ((buffer[k] == ' ') || (buffer[k] == '\t') || (buffer[k] == '\r')) k++;

		l = k;

		if (buffer[k] == '\n') {
			buffer[k] = '\0';
		} else {
			while (buffer[l] != '\n') {
				if (buffer[l] == '#') {
					len = l + 1;
					buffer[l] = '\n';
					break;
				}
				l++;
			}
			buffer[l] = '\0';
			l--;

			sp = false;
			// rtrim key
			while ((buffer[l] == ' ') || (buffer[l] == '\t') || (buffer[l] == '\r')) {
				l--;
				sp = true;
			}
			if (sp) buffer[l + 1] = '\0';
		}

		// printf("\"%s\" = \"%s\"\n", &(buffer[j]), &(buffer[k]));
		if (!strcmp(&(buffer[j]), "dev")) {
			strcpy(internal_buf, &(buffer[k]));
			config->dev = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else if (!strcmp(&(buffer[j]), "mtu")) {
			config->mtu = (uint16_t)atoi(&(buffer[k]));
		} else if (!strcmp(&(buffer[j]), "server_ip")) {
			strcpy(internal_buf, &(buffer[k]));
			config->server_ip = internal_buf;
			internal_buf += strlen(internal_buf) + 1;
		} else if (!strcmp(&(buffer[j]), "server_port")) {
			config->server_port = (uint16_t)atoi(&(buffer[k]));
		} else if (!strcmp(&(buffer[j]), "username")) {
			strcpy(internal_buf, &(buffer[k]));
			config->username = internal_buf;
			config->username_len = strlen(internal_buf);
			internal_buf +=  config->username_len + 1;
		} else if (!strcmp(&(buffer[j]), "password")) {
			strcpy(internal_buf, &(buffer[k]));
			config->password = internal_buf;
			config->password_len = strlen(internal_buf);
			internal_buf += config->password_len;
		}

		line++;
	}


	ret:
	fclose(h);

	return ret;
}
