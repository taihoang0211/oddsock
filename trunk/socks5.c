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

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include "util.h"
#include "oddsock.h"
#include "socks5.h"

#define LISTEN_BACKLOG (128)

void socks5_conn_free(struct socks5_conn *sconn);

int socks5_process_greeting(struct socks5_conn *sconn);
unsigned char socks5_choose_auth_method(struct socks5_conn *sconn,
		unsigned char *methods, unsigned char nmethods);
void socks5_client_readcb(struct bufferevent *bev, void *arg);
void socks5_client_eventcb(struct bufferevent *bev, short what, void *arg);
void socks5_dst_readcb(struct bufferevent *bev, void *arg);
void socks5_dst_eventcb(struct bufferevent *bev, short what, void *arg);

/*
 * socks5_create_listener_socket
 */
int socks5_create_listener_socket(int af)
{
	int e = 0;
	int s = -1; /* The listen socket. */
	const char *cause = NULL; /* Determine the cause of error. */
	struct addrinfo hints; /* Passed to getaddrinfo(). */
	struct addrinfo *res, *res0; /* Results of address lookup. */
	char listen_address[INET6_ADDRSTRLEN];
	unsigned short listen_port = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	e = getaddrinfo(g_opts.listen_address, g_opts.listen_port,
			&hints, &res0);
	if (e != 0) {
		oddsock_error(EXIT_FAILURE, 0, "create_listener_socket getaddrinfo %s",
				gai_strerror(e));
		/*NOTREACHED*/
	}

	for (res = res0; res; res = res->ai_next)
	{
		/* Try to create a socket. */
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			cause = "listen socket creation failed";
			continue;
		}

		/* Set socket to be non-blocking and allow address reuse. */
		if (make_socket_nonblocking(s) < 0) {
			cause = "listen socket could not be set non-blocking";
			s = -1;
			continue;
		}
		if (make_listen_socket_reuseable(s) < 0) {
			cause = "listen socket could not allow reusing addresses";
			s = -1;
			continue;
		}

		/* Try to bind the socket. */
		e = bind(s, res->ai_addr, res->ai_addrlen);
		if (e != 0) {
			cause = "listen socket bind failed";
			s = -1;
			continue;
		}

		sockaddr_to_presentation(res->ai_addr, listen_address,
				sizeof(listen_address), &listen_port);
		oddsock_logx(1, "listening socket bound to address %s port %u",
				listen_address, listen_port);

		break;
	}
	freeaddrinfo(res0);

	/* Ensure that a socket was created and bound. */
	if (s < 0) 
		oddsock_error(EXIT_FAILURE, errno, cause);

	if (listen(s, LISTEN_BACKLOG) < 0)
		oddsock_error(EXIT_FAILURE, errno, "failed to listen");

	return s;
}

/*
 * socks5_listener_accept
 */
void socks5_listener_accept(int listener, short what, void *arg)
{
	struct event_base *base = (struct event_base*)arg;
	int fd = -1; /* fd for accepted connection */
	struct sockaddr_storage ssaddr;
	socklen_t ssaddr_len = sizeof(ssaddr);
	char addr[INET6_ADDRSTRLEN];
	unsigned short port;
	struct socks5_conn *sconn = NULL;
	struct timeval tv;

	if (listener < 0 || !base) {
		oddsock_logx(0, "socks5_listener_accept inavlid args");
		return;
	}

	memset(&ssaddr, 0, sizeof(ssaddr));

	fd = accept(listener, (struct sockaddr*)&ssaddr, &ssaddr_len);
	if (fd < 0) {
		oddsock_log(1, errno, "accept failed");
		return;
	}

	if (g_opts.verbosity > 0) {
		sockaddr_to_presentation((struct sockaddr*)&ssaddr,
				addr, sizeof(addr), &port);
		oddsock_logx(1, "accepted connection from %s port %u", addr, port);
	}

	if (make_socket_nonblocking(fd) < 0) {
		oddsock_logx(1, "failed setting accepted socket to nonblocking");
		return;
	}

	sconn = (struct socks5_conn*)malloc(sizeof(struct socks5_conn));
	if (!sconn) {
		oddsock_logx(1, "failed allocating socks5_conn");
		return;
	}
	memset(sconn, 0, sizeof(struct socks5_conn));

	sconn->status = SCONN_INIT;

	sconn->client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!sconn->client) {
		oddsock_logx(1, "failed creating client bufferevent");
		socks5_conn_free(sconn);
		return;
	}

	bufferevent_setcb(sconn->client, socks5_client_readcb, NULL,
			socks5_client_eventcb, (void*)sconn);

	/* Set a read timeout so that clients that connect but don't send
	 * anything are disconnected. */
	tv.tv_sec = 5; /* 5 second timeout OPTION */
	tv.tv_usec = 0;
	bufferevent_set_timeouts(sconn->client, &tv, NULL);

	if (bufferevent_enable(sconn->client, EV_READ|EV_WRITE) != 0) {
		oddsock_logx(1, "failed to enable read/write on client");
		socks5_conn_free(sconn);
		return;
	}
}

/*
 * socks5_conn_free
 */
void socks5_conn_free(struct socks5_conn *sconn)
{
	if (sconn) {
		if (sconn->client)
			bufferevent_free(sconn->client);
		if (sconn->dst)
			bufferevent_free(sconn->dst);
		memset(sconn, 0, sizeof(struct socks5_conn));
		free(sconn);
	}
}

/*
 * socks5_process_greeting
 * returns:
 *	-1 = error
 *	0  = incomplete
 *	1  = complete
 */
int socks5_process_greeting(struct socks5_conn *sconn)
{
	struct evbuffer *buffer;
	size_t have;
	unsigned char greeting[2];
	unsigned char nmethods;
	unsigned char *methods = NULL;
	unsigned char greeting_reply[2];

	if (sconn->status != SCONN_INIT)
		return -1;
	
	buffer = bufferevent_get_input(sconn->client);
	have = evbuffer_get_length(buffer);

	if (have < 1)
		return 0;

	/* Check version field. */
	evbuffer_copyout(buffer, (void*)greeting, 1);
	if (greeting[0] != 0x05)
		return -1;

	if (have < 2)
		return 0;

	/* Get number of methods. */
	evbuffer_copyout(buffer, (void*)greeting, 2);
	nmethods = greeting[1];

	if (have < (2 + nmethods))
		return 0;
	else if (have > (2 + nmethods))
		return -1;

	/* Finally, get the list of supported methods. */
	methods = (unsigned char*)malloc(nmethods);
	if (!methods)
		return -1;

	evbuffer_drain(buffer, sizeof(greeting));
	evbuffer_remove(buffer, (void*)methods, nmethods);

	/* Choose which auth method to use. */
	sconn->auth_method = socks5_choose_auth_method(sconn, methods, nmethods);
	free(methods);

	/* Respond with chosen method. */
	greeting_reply[0] = 0x05;
	greeting_reply[1] = sconn->auth_method;
	if (bufferevent_write(sconn->client,
				greeting_reply, sizeof(greeting_reply)) != 0)
		return -1;
	
	/* XXX If chosen auth method is "unacceptable" then perhaps a timer
	 * should be set that when expired closes the connection. */

	/* Set new connection state. */
	if (sconn->auth_method != SOCKS5_AUTH_UNACCEPTABLE) {
		sconn->status = SCONN_AUTHORIZED;
	} else {
		/* rfc1928 says that the client MUST close the conneciton. */
		sconn->status = SCONN_CLIENT_MUST_CLOSE;
	}

	return 1;
}

/*
 * socks5_choose_auth_method
 */
unsigned char socks5_choose_auth_method(struct socks5_conn *sconn,
		unsigned char *methods, unsigned char nmethods)
{
	unsigned char i;
	unsigned char method = SOCKS5_AUTH_UNACCEPTABLE;

	if (!sconn || !methods)
		return method;

	for (i = 0; i < nmethods; ++i) {
		if (methods[i] == SOCKS5_AUTH_NONE) {
			method = SOCKS5_AUTH_NONE;
			break;
		}
	}

	return method;
}

/*
 * socks5_client_readcb
 */
void socks5_client_readcb(struct bufferevent *bev, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;
	int e;

	if (!sconn || !bev) {
		oddsock_logx(0, "socks5_client_readcb invalid args");
		return;
	}

	if (sconn->status == SCONN_INIT) {
		e = socks5_process_greeting(sconn);
		if (e < 0) {
			oddsock_logx(1, "error processing client greeting");
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_AUTHORIZED) {
	}
	else if (sconn->status == SCONN_CLIENT_MUST_CLOSE) {
		/* The client MUST close the connection yet it is still sending
		 * something so close the connection. */
		socks5_conn_free(sconn);
	}
}

/*
 * socks5_client_eventcb
 */
void socks5_client_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn || !bev) {
		oddsock_logx(0, "socks5_client_eventcb invalid args");
		return;
	}

	if (what & BEV_EVENT_EOF) {
		/* Client closed the connection. */
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_ERROR) {
		oddsock_log(0, errno, "client connection error");
	}
}

/*
 * socks5_dst_readcb
 */
void socks5_dst_readcb(struct bufferevent *bev, void *arg)
{
}

/*
 * socks5_dst_eventcb
 */
void socks5_dst_eventcb(struct bufferevent *bev, short what, void *arg)
{
}

