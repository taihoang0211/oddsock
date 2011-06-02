/*******************************************************************************
 *
 * oddsock
 * A flexible SOCKS proxy server.
 *
 * Copyright 2011 Stephen Larew. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY STEPHEN LAREW ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL STEPHEN LAREW OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of Stephen Larew.
 *
 ******************************************************************************/

#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <event2/event.h>
#include "util.h"
#include "oddsock.h"
#include "socks5.h"

/*
 * Global program options.
 */

struct oddsock_opts g_opts = {
#ifdef DEBUG
	1, /* verbose */
#else
	0,	/* verbose */
#endif
	true,	/* use_IPv4 */
	true,	/* use_IPv6 */
	"localhost", /* listen_address */
	"socks"	/* listen_port */
};

/*
 * print_usage
 */
void print_usage()
{
	printf("Usage: \n\n");
	exit(EX_USAGE);
}

/*
 * main
 */
int main(int argc, char* argv[])
{
	int opt;
	const char *shortopts = "46v";
	struct option longopts[] = {
		{ "listenAddress",	required_argument,	NULL,	'b'	},
		{ "listenPort",		required_argument,	NULL,	'p'	},
		{ NULL,				0,					NULL,	0	}};
	struct event_base *base = NULL;
	struct event *listener4_event = NULL;
	struct event *listener6_event = NULL;
	int listener4 = -1;
	int listener6 = -1;

	/*
	 * Parse program options.
	 */
	while ((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1)
	{
		switch (opt)
		{
		case '4':
			g_opts.use_IPv6 = false;
			break;
		case '6':
			g_opts.use_IPv4 = false;
			break;
		case 'b':
			g_opts.listen_address = optarg;
			break;
		case 'p':
			g_opts.listen_port = optarg;
			break;
		case 'v':
			g_opts.verbosity = 1;
			break;
		case ':':
			oddsock_logx(0, "Missing option argument.");
			print_usage();
		case '?':
		default:
			print_usage();
		}
	}

	if (!g_opts.use_IPv4 && ! g_opts.use_IPv6) {
		oddsock_logx(0, "Invalid arguments: -4  and -6");
		print_usage();
	}

	oddsock_logx(1, "Program options:\n"
			"\tuse_IPv4 = %u\n"
			"\tuse_IPv6 = %u\n"
			"\tlisten_address = %s\n"
			"\tlisten_port = %s",
			g_opts.use_IPv4, g_opts.use_IPv6,
			g_opts.listen_address, g_opts.listen_port);

	/*
	 * Set up libevent.
	 */

	base = event_base_new();
	if (!base) {
		oddsock_error(EXIT_FAILURE, 0, "failed to create event_base");
		/*NOTREACHED*/
	}

	/*
	 * Create the listener sockets and add events.
	 */

	if (g_opts.use_IPv4) {
		listener4 = socks5_create_listener_socket(AF_INET);

		listener4_event = event_new(base, listener4, EV_READ|EV_PERSIST,
				socks5_listener_accept, (void*)base);
		if (!listener4_event) {
			oddsock_error(EXIT_FAILURE, 0, "failed to create listener4_event");
			/*NOTREACHED*/
		}

		if (event_add(listener4_event, NULL) != 0) {
			oddsock_error(EXIT_FAILURE, 0, "failed to add listner4_event");
			/*NOTREACHED*/
		}
	}
	if (g_opts.use_IPv6) {
		listener6 = socks5_create_listener_socket(AF_INET6);

		listener6_event = event_new(base, listener6, EV_READ|EV_PERSIST,
				socks5_listener_accept, (void*)base);
		if (!listener6_event) {
			oddsock_error(EXIT_FAILURE, 0, "failed to create listener6_event");
			/*NOTREACHED*/
		}

		if (event_add(listener6_event, NULL) != 0) {
			oddsock_error(EXIT_FAILURE, 0, "failed to add listner6_event");
			/*NOTREACHED*/
		}
	}

	event_base_dispatch(base);

	/* cleanup */
	if (listener4_event) {
		event_free(listener4_event);
		listener4_event = NULL;
	}
	if (listener6_event) {
		event_free(listener6_event);
		listener6_event = NULL;
	}
	event_base_free(base);
	base = NULL;

	return EXIT_SUCCESS;
}

