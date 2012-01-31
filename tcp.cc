#include "tcp.h"
#include <cstring>
#include <string>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include "log_facility.h"

int is_ipv4_address(const char *addr)
{
	while ((*addr>='0' && *addr<='9') || *addr=='.') addr++;
	return (*addr==0);
}

int tcp_connect(const char *hoststring)
{
	int sock;
	struct hostent *he;
	struct sockaddr_in addr;
	struct in_addr ip;
	char host[256];
	unsigned port=80;
	int len;
	const char *sep;

	if ((sep=strchr(hoststring,':'))!=NULL)
	{
		len = sep-hoststring;

		if (len>255) len=255;
		memcpy(host,hoststring,len);
		host[len]=0;
		port = atoi(sep+1);
	}
	else
	{
		len = strlen(hoststring);
		if (len>255) len=255;
		memcpy(host,hoststring,len);
		host[len]=0;
	}

	memset(&addr,0,sizeof(addr));
	if (is_ipv4_address(host)) /* assume dotted ip addr */
	{
		if (!inet_aton(host,&ip)) {
			logger.message(logger.ERROR,"inet_aton() failed on '%s'",host);
			return -1;
		}
		addr.sin_addr = ip;
	}
	else /* hostname */
	{
		he = gethostbyname(host);
		if (he==NULL) {
			logger.message(logger.ERROR,"gethostbyname() failed on '%s'",host);
			return -1;
		}
		addr.sin_addr   = *(struct in_addr*)he->h_addr_list[0];
	}
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(port);

	sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if (sock<0) {
		logger.message(logger.ERROR,"socket() failed on destination '%s:%u', %s",host,port,strerror(errno));
		return sock;
	}
	if (connect(sock,(struct sockaddr *)&addr,sizeof(addr))<0) {
		logger.message(logger.ERROR,"connect() failed on destination '%s:%u', %s",host,port,strerror(errno));
		return -1;
	}
	return sock;
}	

int tcp_listen(unsigned port)
{
	int sock;
	struct sockaddr_in sin;
	
	sock = socket(AF_INET,SOCK_STREAM,0);
	if (sock<0) {
		logger.message(logger.ERROR,"socket() failed for proxy, %s",strerror(errno));
		return sock;
	}
	memset(&sin,0,sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0) {
		logger.message(logger.ERROR,"bind() failed for proxy, %s",strerror(errno));
		return -1;
	}
	listen(sock,5);
	return sock;
}

int tcp_accept(int sock, char *caller)
{
	int s;
	socklen_t alen;
	struct sockaddr_in sin;

	alen = sizeof(sin);
	s = accept(sock,(struct sockaddr *)&sin,&alen);
	if (caller)
		sprintf(caller,"%s:%u",inet_ntoa(sin.sin_addr),ntohs(sin.sin_port));
	return s;
}

const char *socket_get_local_ip(int sock)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    if (getsockname(sock,(struct sockaddr *)&sin,&sin_len)!=0)
	return NULL;
    return inet_ntoa(sin.sin_addr);
}

unsigned short socket_get_local_port(int sock)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    if (getsockname(sock,(struct sockaddr *)&sin,&sin_len)!=0)
	return 0;
    return ntohs(sin.sin_port);
}

const char *socket_get_peer_ip(int sock)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    if (getpeername(sock,(struct sockaddr *)&sin,&sin_len)!=0)
	return NULL;
    return inet_ntoa(sin.sin_addr);
}

unsigned short socket_get_peer_port(int sock)
{
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    if (getpeername(sock,(struct sockaddr *)&sin,&sin_len)!=0)
	return 0;
    return ntohs(sin.sin_port);
}

