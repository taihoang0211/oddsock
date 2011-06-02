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

#ifndef ODDSOCK_UTIL_H
#define ODDSOCK_UTIL_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>

void oddsock_log(unsigned int level, int errnum, const char *fmt, ...);
void oddsock_logx(unsigned int level, const char *fmt, ...);
void oddsock_error(int status, int errnum, const char *fmt, ...);

int make_socket_nonblocking(int s);
int make_listen_socket_reuseable(int s);
int sockaddr_to_presentation(struct sockaddr *saddr, char *addr,
		int addrlen, unsigned short *port);

#endif

