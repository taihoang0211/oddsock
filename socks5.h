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
 e******************************************************************************/

#ifndef ODDSOCK_SOCKS5_H
#define ODDSOCK_SOCKS5_H

#include <event2/bufferevent.h>

enum socks5_conn_status {
	SCONN_INIT = 0,
	SCONN_CLIENT_MUST_CLOSE,
	SCONN_AUTHORIZED,
	SCONN_CONNECT_WAIT,
	SCONN_CONNECT_TRANSMITTING
};

#define SOCKS5_AUTH_NONE			(0x00)
#define SOCKS5_AUTH_UNACCEPTABLE	(0xFF)

#define SOCKS5_CMD_CONNECT		(0x01)
#define SOCKS5_CMD_BIND			(0x02)
#define SOCKS5_CMD_UDP_ASSOC	(0x03)
#define SOCKS5_CMD_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x04))

#define SOCKS5_ATYPE_IPV4	(0x01)
#define SOCKS5_ATYPE_DOMAIN	(0x03)
#define SOCKS5_ATYPE_IPV6	(0x04)
#define SOCKS5_ATYPE_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x05) && ((cmd) != 0x02))

#define SOCKS5_REP_SUCCEEDED			(0x00)
#define SOCKS5_REP_GENERAL_FAILURE		(0x01)
#define SOCKS5_REP_NOT_ALLOWED			(0x02)
#define SOCKS5_REP_NET_UNREACHABLE		(0x03)
#define SOCKS5_REP_HOST_UNREACHABLE		(0x04)
#define SOCKS5_REP_CONN_REFUSED			(0x05)
#define SOCKS5_REP_TTL_EXPIRED			(0x06)
#define SOCKS5_REP_BAD_COMMAND			(0x07)
#define SOCKS5_REP_ATYPE_UNSUPPORTED	(0x08)

/*
 * socks5_conn
 */
struct socks5_conn {
	struct bufferevent *client;
	struct bufferevent *dst;
	enum socks5_conn_status status;
	unsigned char auth_method;
	unsigned char command;
};

/*
 * socks5_create_listener_socket
 * Create and bind the server listener socket.
 */
int socks5_create_listener_socket(int af);

/*
 * socks5_listener_accept
 * Calls accept on a listener socket and begins the SOCKS 5 protocol.
 */
void socks5_listener_accept(int listener, short what, void *base);

#endif

