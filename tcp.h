#ifndef TCP_H
#define TCP_H

int tcp_connect(const char *hoststring);
int tcp_listen(unsigned port);
int tcp_accept(int sock, char *caller);

const char *socket_get_local_ip(int sock);
unsigned short socket_get_local_port(int sock);
const char *socket_get_peer_ip(int sock);
unsigned short socket_get_peer_port(int sock);

#endif
