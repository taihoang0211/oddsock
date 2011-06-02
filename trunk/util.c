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

#include <stdarg.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "util.h"
#include "oddsock.h"

#define ODDSOCK_LOG_BUFFER 512

void oddsock_log(unsigned int level, int errnum, const char *fmt, ...)
{
	if (level <= g_opts.verbosity)
	{
		va_list ap;
		char s[ODDSOCK_LOG_BUFFER];

		strcpy(s, "oddsock: ");

		va_start(ap, fmt);
		vsnprintf(&s[strlen(s)], ODDSOCK_LOG_BUFFER - strlen(s), fmt, ap);
		va_end(ap);

		if (errnum != 0) {
			strlcat(s, " - errno: ", ODDSOCK_LOG_BUFFER);
			strlcat(s, strerror(errnum), ODDSOCK_LOG_BUFFER);
		}

		fprintf(stdout, "%s\n", s);
	}
}

void oddsock_logx(unsigned int level, const char *fmt, ...)
{
	if (level <= g_opts.verbosity)
	{
		va_list ap;
		char s[ODDSOCK_LOG_BUFFER];

		strcpy(s, "oddsock: ");

		va_start(ap, fmt);
		vsnprintf(&s[strlen(s)], ODDSOCK_LOG_BUFFER - strlen(s), fmt, ap);
		va_end(ap);

		fprintf(stdout, "%s\n", s);
	}
}

void oddsock_error(int status, int errnum, const char *fmt, ...)
{
	va_list ap;
	char s[ODDSOCK_LOG_BUFFER];

	strcpy(s, "oddsock: ERROR ");

	va_start(ap, fmt);
	vsnprintf(&s[strlen(s)], ODDSOCK_LOG_BUFFER - strlen(s), fmt, ap);
	va_end(ap);

	if (errnum != 0) {
		strlcat(s, " - errno: ", ODDSOCK_LOG_BUFFER);
		strlcat(s, strerror(errnum), ODDSOCK_LOG_BUFFER);
	}

	fprintf(stderr, "%s\n", s);

	if (status != 0)
		exit(status);
	else
		return;
}

int make_socket_nonblocking(int s)
{
	int flags;
	if ((flags = fcntl(s, F_GETFL, NULL)) < 0) {
		oddsock_log(0, errno, "make_socket_nonblocking fcntl(F_GETFL)");
		return -1;
	}
	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
		oddsock_log(0, errno, "make_sock_nonblocking fcntl(F_SETFL)");
		return -1;
	}
	return 0;
}

int make_listen_socket_reuseable(int s)
{
	const int one = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			(const void*)&one, (socklen_t)sizeof(one)) < 0) {
		oddsock_log(0, errno, __FUNCTION__);
		return -1;
	}
	return 0;
}

int sockaddr_to_presentation(struct sockaddr *saddr, char *addr,
		int addrlen, unsigned short *port)
{
	if (!saddr)
		return -1;

	if (saddr->sa_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in*)saddr;
		if (addr)
			if (!inet_ntop(AF_INET, &addr4->sin_addr, addr, addrlen)) {
				oddsock_log(0, errno, __FUNCTION__);
				return -1;
			}
		if (port)
			*port = ntohs(addr4->sin_port);
	} else if (saddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)saddr;
		if (addr)
			if (!inet_ntop(AF_INET6, &addr6->sin6_addr, addr, addrlen)) {
				oddsock_log(0, errno, __FUNCTION__);
				return -1;
			}
		if (port)
			*port = ntohs(addr6->sin6_port);
	} else {
		if (addr)
			strcpy(addr, "unknown");
		if (port)
			*port = 0;
	}
	return 0;
}

