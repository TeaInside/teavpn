
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <teavpn/cli_arg.h>

static const struct option server_options[] = {
	{"address",			required_argument,		0,		'h'},
	{"port",			required_argument,		0,		'p'},
	{"threads",			required_argument,		0,		't'},
	{"config",			required_argument,		0,		'c'},
	{"config-file",		required_argument,		0,		'c'},
	{"error-log",		required_argument,		0,		0x1},
	{"verbose",			required_argument,		0,		0x2},
	{"dev",				required_argument,		0,		0x3},
	{"help",			no_argument,			0,		0xa},
	{0, 0, 0, 0}
};

static const struct option client_options[] = {
	{"address",			required_argument,		0,		'h'},
	{"sever-ip",		required_argument,		0,		'h'},
	{"port",			required_argument,		0,		'p'},
	{"config",			required_argument,		0,		'c'},
	{"config-file",		required_argument,		0,		'c'},
	{"error-log",		required_argument,		0,		0x1},
	{"verbose",			required_argument,		0,		0x2},
	{"dev",				required_argument,		0,		0x3},
	{"help",			no_argument,			0,		0xa},
	{0, 0, 0, 0}
};

static char bind_any_addr[] = "0.0.0.0";
static char default_dev_name[] = "teavpn";
static char default_inet4[] = "5.5.0.1/16";

static void show_help_client(char *appname);
static void show_help_server(char *appname);
static void show_help_command(char *appname);
static bool server_argv_parser(char *appname, server_config *server, int argc, char **argv, char **envp);
static bool client_argv_parser(char *appname, client_config *client, int argc, char **argv, char **envp);

/**
 * @param teavpn_config		*config
 * @param int				int
 * @param char				**argv
 * @param char				**envp
 * return bool
 */
bool argv_parser(teavpn_config *config, int argc, char **argv, char **envp)
{
	if (argc == 1) {
		show_help_command(argv[0]);
		return false;
	}

	if (!strcmp(argv[1], "server")) {
		config->type = teavpn_server_config;
		return server_argv_parser(argv[0], &(config->config.server), argc - 1, &(argv[1]), envp);
	} else if (!strcmp(argv[1], "connect")) {
		config->type = teavpn_client_config;
		return client_argv_parser(argv[0], &(config->config.client), argc - 1, &(argv[1]), envp);
	} else if (
		(!strcmp(argv[1], "--help")) || (!strcmp(argv[1], "-h")) || (!strcmp(argv[1], "help"))
	) {
		show_help_command(argv[0]);
	} else {
		printf("Invalid command \"%s\"!\n\nShow usage: %s --help\n", argv[1], argv[0]);
	}

	return false;
}

/**
 * @param char				*appname
 * @param teavpn_config		*server
 * @param int				int
 * @param char				**argv
 * @param char				**envp
 * return bool
 */
static bool server_argv_parser(char *appname, server_config *server, int argc, char **argv, char **envp)
{
	int c, option_index;

	// Set default config.
	server->bind_addr = bind_any_addr;
	server->bind_port = 55555;
	server->threads = 8;
	server->verbose_level = 0;
	server->error_log_file = NULL;
	server->config_file = NULL;
	server->mtu = 1500;
	server->inet4 = default_inet4;
	server->dev = default_dev_name;

	while (true) {

		option_index = 0;
		c = getopt_long(argc, argv, "h:p:t:vc:", server_options, &option_index);
		if (c == -1) break;

		switch (c) {
			case 'h':
				server->bind_addr = optarg;
				break;

			case 'p':
				server->bind_port = (uint16_t)atoi(optarg);
				break;

			case 't':
				server->threads = (uint8_t)atoi(optarg);
				break;

			case 'v':
				server->verbose_level++;
				break;

			case 'c':
				server->config_file = optarg;
				break;

			case 0x1:
				server->error_log_file = optarg;
				break;

			case 0x2:
				server->verbose_level = (uint8_t)atoi(optarg);
				break;

			case 0x3:
				server->dev = optarg;
				break;

			case 0xa:
				show_help_server(appname);
				break;

			default:
				fprintf(stderr, "Fatal error: getopt_long returned unknown value!\n");
				return false;
				break;
		}
	}

	#ifdef TEAVPN_DEBUG
		// Debug arguments
		printf("[debug cli args]\n");
		printf("bind_addr: %s\n", server->bind_addr);
		printf("bind_port: %d\n", server->bind_port);
		printf("threads: %d\n", server->threads);
		printf("error_log_file: %s\n", server->error_log_file);
		printf("dev_name: %s\n", server->dev);
		printf("config_file: %s\n\n\n", server->config_file);
		fflush(stdout);
	#endif

	return true;
}

/**
 * @param char				*appname
 * @param client_config		*client
 * @param int				int
 * @param char				**argv
 * @param char				**envp
 * return bool
 */
static bool client_argv_parser(char *appname, client_config *client, int argc, char **argv, char **envp)
{
	int c, option_index;

	// Set default config.
	client->server_ip = NULL;
	client->server_port = 55555;
	client->verbose_level = 0;
	client->error_log_file = NULL;
	client->config_file = NULL;
	client->mtu = 1500;
	client->inet4 = NULL;
	client->dev = default_dev_name;

	while (true) {

		option_index = 0;
		c = getopt_long(argc, argv, "h:p:vc:", server_options, &option_index);
		if (c == -1) break;

		switch (c) {
			case 'h':
				client->server_ip = optarg;
				break;

			case 'p':
				client->server_port = (uint16_t)atoi(optarg);
				break;

			case 'v':
				client->verbose_level++;
				break;

			case 'c':
				client->config_file = optarg;
				break;

			case 0x1:
				client->error_log_file = optarg;
				break;

			case 0x2:
				client->verbose_level = (uint8_t)atoi(optarg);
				break;

			case 0x3:
				client->dev = optarg;
				break;

			case 0xa:
				show_help_client(appname);
				break;

			default:
				fprintf(stderr, "Fatal error: getopt_long returned unknown value!\n");
				return false;
				break;
		}
	}

	#ifdef TEAVPN_DEBUG
		// Debug arguments
		printf("[debug cli args]\n");
		printf("bind_addr: %s\n", client->server_ip);
		printf("bind_port: %d\n", client->server_port);
		printf("error_log_file: %s\n", client->error_log_file);
		printf("dev_name: %s\n", client->dev);
		printf("config_file: %s\n\n\n", client->config_file);
		fflush(stdout);
	#endif

	return true;
}

/**
 * @return void
 */
static void show_help_command(char *appname)
{
	printf("Usage: %s [command] [options]\n\n", appname);
	printf("Available commands:\n");
	printf("\tserver\t\tMake TeaVPN server.\n");
	printf("\tconnect\t\tConnect to TeaVPN server.\n");
	printf("\nDetailed information: %s [command] --help\n", appname);
	fflush(stdout);
}

/**
 * @return void
 */
static void show_help_server(char *appname)
{
	printf("Usage: %s server [options]\n\n", appname);
	printf("Available options:\n");
	printf("\t--address, -h\t\tSet bind address (default 0.0.0.0).\n");
	printf("\t--port, -p\t\tSet bind port (default 55555).\n");
	printf("\t--threads, -t\t\tSet threads amount (default 8).\n");
	fflush(stdout);
}

/**
 * @return void
 */
static void show_help_client(char *appname)
{
	printf("Usage: %s connect [options]\n\n", appname);
	printf("Available options:\n");
	printf("\t--address, -h\t\tSet bind address.\n");
	printf("\t--port, -p\t\tSet bind port (default 55555).\n");
	fflush(stdout);
}
