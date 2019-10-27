
/**
 * @author Ammar Faizi <ammarfaizi2@gmail.com> https://www.facebook.com/ammarfaizi2
 * @license MIT
 * @package TeaVPN
 */

#ifndef __teavpn__cli_arg_h
#define __teavpn__cli_arg_h

#include <teavpn/teavpn.h>

bool argv_parser(teavpn_config *config, int argc, char **argv, char **envp);

#endif
