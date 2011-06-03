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
#include <arpa/inet.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include "util.h"
#include "oddsock.h"
#include "socks5.h"

#define LISTEN_BACKLOG (128)

struct evdns_base *g_dns_base = NULL;

int socks5_conn_id(struct socks5_conn *sconn);
void socks5_conn_free(struct socks5_conn *sconn);

int socks5_process_greeting(struct socks5_conn *sconn);
void socks5_choose_auth_method(struct socks5_conn *sconn,
		unsigned char *methods, unsigned char nmethods);
int socks5_process_request(struct socks5_conn *sconn);
int socks5_connect_reply(struct socks5_conn *sconn);
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
		oddsock_logx(1, "(%d) accepted connection from %s port %u",
				fd, addr, port);
	}

	if (make_socket_nonblocking(fd) < 0) {
		oddsock_logx(1,
				"(%d) failed setting accepted socket to nonblocking", fd);
		return;
	}

	sconn = (struct socks5_conn*)malloc(sizeof(struct socks5_conn));
	if (!sconn) {
		oddsock_logx(1, "(%d) failed allocating socks5_conn", fd);
		return;
	}
	memset(sconn, 0, sizeof(struct socks5_conn));

	sconn->status = SCONN_INIT;

	sconn->client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!sconn->client) {
		oddsock_logx(1, "(%d) failed creating client bufferevent", fd);
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
		oddsock_logx(1, "(%d) failed to enable read/write on client", fd);
		socks5_conn_free(sconn);
		return;
	}
}

/*
 * socks5_conn_id
 */
int socks5_conn_id(struct socks5_conn *sconn)
{
	if (!sconn || !sconn->client)
		return -1;

	return bufferevent_getfd(sconn->client);
}

/*
 * socks5_conn_free
 */
void socks5_conn_free(struct socks5_conn *sconn)
{
	if (sconn) {
		oddsock_logx(1, "(%d) freeing connections", socks5_conn_id(sconn));
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

	if (!sconn ||
		sconn->status != SCONN_INIT ||
		!sconn->client)
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
	evbuffer_remove(buffer, (void*)methods, nmethods); /* XXXerr */

	/* Choose which auth method to use. */
	socks5_choose_auth_method(sconn, methods, nmethods);
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
void socks5_choose_auth_method(struct socks5_conn *sconn,
		unsigned char *methods, unsigned char nmethods)
{
	unsigned char i;
	unsigned char method = SOCKS5_AUTH_UNACCEPTABLE;

	for (i = 0; i < nmethods; ++i) {
		if (methods[i] == SOCKS5_AUTH_NONE) {
			method = SOCKS5_AUTH_NONE;
			break;
		}
	}

	sconn->auth_method = method;
}

/*
 * socks5_process_request
 */
int socks5_process_request(struct socks5_conn *sconn)
{
	struct evbuffer *buffer;
	size_t have;
	unsigned char request[6+256]; /* fixed + variable address */
	unsigned char request_reply[2] = { 0x05, 0x00 };
	unsigned char atype;
	int af;
	char addr[256]; /* max(unsigned char) + NULL terminator */
	unsigned short port;

	if (!sconn ||
		sconn->status != SCONN_AUTHORIZED ||
		!sconn->client)
		return -1;
	
	buffer = bufferevent_get_input(sconn->client);
	have = evbuffer_get_length(buffer);

	if (have < 1)
		return 0;
	evbuffer_copyout(buffer, (void*)request, 1);

	/* Check version field. */
	if (request[0] != 0x05)
		return -1;

	if (have < 8)
		return 0;
	evbuffer_copyout(buffer, (void*)request, 8);

	/* Get command and address type. */
	if (!SOCKS5_CMD_VALID(request[1])) {
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}
	sconn->command = request[1];

	if (!SOCKS5_ATYPE_VALID(request[3])) {
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}
	atype = request[3];

	/* Get the address and port. */
	if (atype == SOCKS5_ATYPE_IPV4) {
		if (have < 10)
			return 0;
		else if (have > 10)
			return -1;

		evbuffer_remove(buffer, (void*)request, 10);

		af = AF_INET;
		if (!inet_ntop(af, &request[4], addr, sizeof(addr))) {
			oddsock_log(1, errno,
					"(%d) inet_ntop failed while processing request",
					socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		port = ntohs(*((unsigned short*)&request[8]));
	}
	else if (atype == SOCKS5_ATYPE_IPV6) {
		if (have < 22)
			return 0;
		else if (have > 22)
			return -1;

		evbuffer_remove(buffer, (void*)request, 22);

		af = AF_INET6;
		if (!inet_ntop(af, &request[4], addr, sizeof(addr))) {
			oddsock_log(1, errno,
					"(%d) inet_ntop failed while processing request",
					socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		port = ntohs(*((unsigned short*)&request[20]));
	}
	else if (atype == SOCKS5_ATYPE_DOMAIN) {
		unsigned char addrlen;

		addrlen = request[4];
		if (have < (7 + addrlen))
			return 0;
		else if (have > (7 + addrlen))
			return -1;

		evbuffer_remove(buffer, (void*)request, (7 + addrlen));

		af = AF_UNSPEC;
		memcpy(addr, &request[5], addrlen);
		addr[addrlen] = '\0';
		port = ntohs(*((unsigned short*)&request[5+addrlen]));
	}

	/* Handle request. */
	if (sconn->command == SOCKS5_CMD_CONNECT) {
		/* CONNECT request. */
		oddsock_logx(1, "(%d) connection request for %s port %u",
				socks5_conn_id(sconn), addr, port);

		/* Create dst bufferevent. */
		sconn->dst = bufferevent_socket_new(
				bufferevent_get_base(sconn->client), -1,
				BEV_OPT_CLOSE_ON_FREE);
		if (!sconn->dst) {
			oddsock_log(1, errno, "(%d) failed creating dst bufferevent",
					socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		bufferevent_setcb(sconn->dst, socks5_dst_readcb, NULL,
				socks5_dst_eventcb, (void*)sconn);

		/* Make sure the DNS resolver is ready. */
		if (!g_dns_base) {
			g_dns_base = evdns_base_new(
					bufferevent_get_base(sconn->client), 1);
			if (!g_dns_base) {
				oddsock_logx(0, "(%d) failed creating evdns_base",
						socks5_conn_id(sconn));
			}
		}

		/* Connect to destination. */
		if (bufferevent_socket_connect_hostname(
					sconn->dst, g_dns_base, af, addr, port) != 0) {
			oddsock_log(1, errno, "(%d) failed creating dst bufferevent",
					socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		sconn->status = SCONN_CONNECT_WAIT;
	}
	else {
		/* Only CONNECT is implemented right now. */
		oddsock_log(1, errno,
				"(%d) unsupported command %u requested",
				socks5_conn_id(sconn), sconn->command);
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}

	return 1;
}

/*
 * socks5_connect_reply
 */
int socks5_connect_reply(struct socks5_conn *sconn)
{
	unsigned char reply[5];
	struct sockaddr_storage ssaddr;
	socklen_t sslen = sizeof(ssaddr);
	int dstfd;

	reply[0] = 0x05;
	dstfd = bufferevent_getfd(sconn->dst);

	memset(&ssaddr, 0, sizeof(ssaddr));
	if (getsockname(dstfd, (struct sockaddr*)&ssaddr, &sslen) < 0) {
		/* Notify client of failure and close. */
		reply[1] = SOCKS5_REP_GENERAL_FAILURE;
		bufferevent_write(sconn->client, reply, 2);
		return -1;
	}

	reply[1] = SOCKS5_REP_SUCCEEDED;
	reply[2] = 0x00;

	if (ssaddr.ss_family == AF_INET) {
		struct sockaddr_in *saddr = (struct sockaddr_in*)&ssaddr;
		reply[3] = SOCKS5_ATYPE_IPV4;
		bufferevent_write(sconn->client, reply, 4); 
		bufferevent_write(sconn->client, &saddr->sin_addr,
				sizeof(saddr->sin_addr));
		bufferevent_write(sconn->client, &saddr->sin_port, 2);
	}
	else if (ssaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6*)&ssaddr;
		reply[3] = SOCKS5_ATYPE_IPV6;
		bufferevent_write(sconn->client, reply, 4); 
		bufferevent_write(sconn->client, &saddr->sin6_addr,
				sizeof(saddr->sin6_addr));
		bufferevent_write(sconn->client, &saddr->sin6_port, 2);
	}
	else {
		/* Notify client of failure and close. */
		reply[1] = SOCKS5_REP_GENERAL_FAILURE;
		bufferevent_write(sconn->client, reply, 2);
		return -1;
	}

	sconn->status = SCONN_CONNECT_TRANSMITTING;

	if (bufferevent_enable(sconn->dst, EV_READ|EV_WRITE) != 0) {
		oddsock_logx(1, "(%d) failed to enable read/write on dst",
				socks5_conn_id(sconn));
		return -1;
	}

	return 0;
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
		bufferevent_set_timeouts(sconn->client, NULL, NULL);

		e = socks5_process_greeting(sconn);
		if (e < 0) {
			oddsock_logx(1, "(%d) error processing client greeting",
					socks5_conn_id(sconn));
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_CLIENT_MUST_CLOSE) {
		/* The client MUST close the connection yet it is still sending
		 * something so close the connection. */
		oddsock_logx(1, "(%d) client not rfc1928 conformant",
				socks5_conn_id(sconn));
		socks5_conn_free(sconn);
	}
	else if (sconn->status == SCONN_AUTHORIZED) {
		e = socks5_process_request(sconn);
		if (e < 0) {
			oddsock_logx(1,"(%d) error processing client request",
					socks5_conn_id(sconn));
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_CONNECT_WAIT) {
		/* Client sent data while waiting on request reply.
		 * Treat this as an errant client and clost connection. */
		oddsock_logx(1, "(%d) errant client", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
	}
	else if (sconn->status == SCONN_CONNECT_TRANSMITTING) {
		bufferevent_read_buffer(sconn->client,
				bufferevent_get_output(sconn->dst));
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

	if (what & BEV_EVENT_TIMEOUT) {
		oddsock_logx(1, "(%d) client timeout", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_EOF) {
		/* Client closed the connection. */
		oddsock_logx(1, "(%d) client closed connection",
				socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_ERROR) {
		oddsock_log(1, errno, "(%d) client connection error",
				socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
}

/*
 * socks5_dst_readcb
 */
void socks5_dst_readcb(struct bufferevent *bev, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn ||
		!sconn->client ||
		!sconn->dst)
		return;

	if (sconn->status == SCONN_CONNECT_TRANSMITTING) {
		bufferevent_read_buffer(sconn->dst,
				bufferevent_get_output(sconn->client));
	}
}

/*
 * socks5_dst_eventcb
 */
void socks5_dst_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn || !bev) {
		oddsock_logx(0, "socks5_dst_eventcb invalid args");
		return;
	}

	if (what & BEV_EVENT_CONNECTED) {
		if (socks5_connect_reply(sconn) < 0) {
			oddsock_logx(1, "(%d) failed sending request reply",
					socks5_conn_id(sconn));
			socks5_conn_free(sconn);
			return;
		}
		oddsock_logx(1, "(%d) CONNECT succeeded", socks5_conn_id(sconn));
		return;
	}
	if (what & BEV_EVENT_EOF) {
		/* Destination closed the connection. */
		oddsock_logx(1, "(%d) destination closed connection",
				socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_ERROR) {
		int e = bufferevent_socket_get_dns_error(bev);
		if (e != 0)
			oddsock_logx(1, "(%d) DNS error: %s",
					socks5_conn_id(sconn), gai_strerror(e));
		else
			oddsock_log(1, errno, "(%d) destination connection error",
					socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
}

