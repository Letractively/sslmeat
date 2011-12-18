#include <vector>
#include <string>
#include <cctype>
#include "bufio.h"
#include "bufio_ssl.h"
#include "log_facility.h"
#include "tcp.h"
#include "ssl_tools.h"
#include "http_packet.h"

/************************/

class HttpProxy {
	public:
		enum proxy_state {
		        PROXY_EXPECT_INIT,
			PROXY_EXPECT_REQUEST,
			PROXY_EXPECT_RESPONSE,
			PROXY_EXPECT_TUNNEL,
			PROXY_EXPECT_SSL_INIT,
			PROXY_EXPECT_SSL_REQUEST,
			PROXY_EXPECT_SSL_RESPONSE,
			PROXY_EXPECT_RESPONSE_GATEWAY_TIMEOUT,
			PROXY_EXPECT_CONNECTION_CLOSE,
			PROXY_EXPECT_ERROR
		};
		static HttpProxy *create(int socket);
		~HttpProxy();
		bool run();
		bool set_secondary_proxy(const std::string &proxy_name);
	private:
		HttpProxy(int socket, proxy_state state = PROXY_EXPECT_INIT) : 
			_client(BufferInOutFile::create(socket)),
			_server(NULL), 
			_last_request(NULL),
			_last_response(NULL),
			_secondary_proxy(false), 
			_proxy_state(state),
   			_target_host("undefined") {}
		BufferInOutFile *_client;
		BufferInOutFile *_server;

		HttpPacket *_last_request;
		HttpPacket *_last_response;

		bool _secondary_proxy;
		proxy_state _proxy_state;
		std::string _secondary_proxy_name;
		std::string _target_host;

		static bool parse_url(const std::string& uri, 
				      std::string& host, std::string& path);

                HttpPacket* process_request(void);
		HttpPacket* process_response_gateway_timeout(void);
		HttpPacket* process_response(void);
		HttpPacket* process_tunnel_setup(void);
		HttpPacket* process_ssl_request(void);
		HttpPacket* process_ssl_response(void);

		HttpProxy* change_state(proxy_state state) 	{ _proxy_state = state; return this; }

		DISALLOW_COPY_AND_ASSIGN(HttpProxy);
};

HttpProxy *HttpProxy::create(int socket)
{
    return new HttpProxy(socket);
}

HttpProxy::~HttpProxy()
{
    if (_client) delete _client;
    if (_server) delete _server;
    if (_last_request) delete _last_request;
    if (_last_response) delete _last_response;
}

/* static */ bool HttpProxy::parse_url(const std::string& uri, std::string& host, std::string& path)
{
    unsigned start;

    start = uri.find("://");
    if (start == std::string::npos)
    {
	host = "";
	path = uri;
	return true;
    }
    start = uri.find('/', start + 3);
    if (start == std::string::npos)
    {
	host = uri;
	path = "";
	return true;
    }
    host.assign(uri,0,start);
    path.assign(uri,start,std::string::npos);
    return true;
}

// 
// PROXY_EXPECT_TUNNEL
//
HttpPacket* HttpProxy::process_tunnel_setup()
{
    int sock;
    X509*     local_server_cert;
    EVP_PKEY* local_client_key	= NULL;
    EVP_PKEY* local_server_key 	= NULL;
    EVP_PKEY* local_ca_key	= NULL;
    X509*     distant_server_cert;
    X509*	  local_ca_cert;
    BufferInOutSSL *tmp;
    std::string description;
    X509*	  cert_chain[2];
    std::string line;
    HttpPacket *packet = NULL;


    if ((local_client_key = openssl_load_private_key_from_file("KEYS/client_key_pair.key","secret"))==NULL)
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_tunnel_setup_end;
    }
    if ((local_server_key = openssl_load_private_key_from_file("KEYS/server_key_pair.key","secret"))==NULL)
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_tunnel_setup_end;	
    }
    if ((local_ca_key = openssl_load_private_key_from_file("KEYS/ca_key_pair.key","secret"))==NULL)
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_tunnel_setup_end;	
    }
    if ((local_ca_cert = openssl_load_cert_from_file("KEYS/ca_cert.pem"))==NULL)
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_tunnel_setup_end;	
    }

    _target_host = _last_request->headline_get_part(1);

    /* if no secondary proxy ... */
    if (!_secondary_proxy)
    {
	sock = tcp_connect(_target_host.c_str());
	if (sock<0)
	{
	    logger.message(logger.WARNING,"failed to establish connection to %s, sending error 504.",_target_host.c_str());	

	    packet = HttpPacket::create();
	    packet->headline_set("HTTP/1.1 504 Gateway timeout\r\n");
	    packet->header_field_add("Proxy-agent: Proxy Certs\r\n");
	    packet->header_field_add("\r\n");
	    packet->packet_write_out(_client);
	    _client->write_flush();
	}
	else
	{	
	    logger.message(logger.DEBUG,"Connected to %s",_target_host.c_str());
	    tmp = BufferInOutSSL::create(sock,false,local_client_key);
	    _server = tmp;
	    if (!_server)
	    {
		change_state(PROXY_EXPECT_ERROR);
		goto process_tunnel_setup_end; /* TODO: release alloc objects */
	    }
	    logger.message(logger.DEBUG,"established SSL client connection to %s",_target_host.c_str());

	    packet = HttpPacket::create();
	    packet->headline_set("HTTP/1.1 200 Connection established\r\n");
	    packet->header_field_add("Proxy-agent: Proxy Certs\r\n");
	    packet->header_field_add("\r\n");
	    packet->packet_write_out(_client);
	    _client->write_flush();
	}
	packet->log();
    }
    else /* if we have a secondary proxy ... */
    {
	if (!_server)
	{
	    sock = tcp_connect(_secondary_proxy_name.c_str());
	    if (sock<0) 
	    {
		change_state(PROXY_EXPECT_ERROR);
		goto process_tunnel_setup_end;
	    }	
	    logger.message(logger.DEBUG,"established connection to secondary proxy %s",_secondary_proxy_name.c_str());
	    _server = BufferInOutFile::create(sock);		    
	}
	else
	{
	    sock = _server->get_fd();
	}

	_last_request->packet_write_out(_server);

	packet = HttpPacket::create();
	packet->packet_read_in(_server);

	logger.message(logger.DEBUG,"Response to CONNECT: %s",packet->headline_get().c_str());

	packet->log();

	packet->packet_write_out(_client);
	_client->write_flush();

	if (packet->headline_get_part(1)!="200")
	{
	    change_state(PROXY_EXPECT_REQUEST);
	    goto process_tunnel_setup_end;
	}

	tmp = BufferInOutSSL::create(sock,false,local_client_key);
	_server = tmp;
	if (!_server)
	{
	    change_state(PROXY_EXPECT_ERROR);
	    goto process_tunnel_setup_end;
	    /* TODO: release alloc objects */
	}

	logger.message(logger.DEBUG,"established SSL client connection to %s trough secondary proxy %s",_target_host.c_str(),_secondary_proxy_name.c_str());
    }

    sock = _client->get_fd();
    delete _client;

    distant_server_cert = SSL_get_peer_certificate(tmp->get_ssl());
    if (distant_server_cert==NULL)
    {
	change_state(PROXY_EXPECT_ERROR);
	logger.message(logger.ERROR,"Failed to get peer certificate");
	goto process_tunnel_setup_end;
    }
    local_server_cert = openssl_transform_certificate(distant_server_cert,local_ca_key,local_server_key);

    /*{
      FILE *X = fopen("save.cert","wb");
      i2d_X509_fp(X,local_server_cert);
      fclose(X);
      }*/

    cert_chain[0]=local_server_cert;
    cert_chain[1]=local_ca_cert;
    tmp = BufferInOutSSL::create(sock, true, local_server_key, 2, cert_chain);
    _client = tmp;
    if (!_client)
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_tunnel_setup_end;
	/* TODO: cleanup */
    }

    packet->hostname_set("[proxy]");
    packet->source_set_ip(socket_get_local_ip(_client->get_fd()));
    packet->source_set_port(socket_get_local_port(_client->get_fd()));
    packet->destination_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->destination_set_port(socket_get_peer_port(_client->get_fd()));
    
    logger.message(logger.DEBUG,"established SSL server connection from %s:%u to %s:%u",
		    packet->source_get_ip(),
		    packet->source_get_port(),
		    packet->destination_get_ip(),
		    packet->destination_get_port()
		    );

    change_state(PROXY_EXPECT_SSL_REQUEST);

process_tunnel_setup_end:

    if (local_ca_key) EVP_PKEY_free(local_ca_key);
    if (local_server_key) EVP_PKEY_free(local_server_key);
    if (local_client_key) EVP_PKEY_free(local_client_key);
    
    if (_last_response && packet)
    {
	delete _last_response;
    	_last_response = packet;
    }
    
    return packet;
}

//
// PROXY_EXPECT_SSL_REQUEST
//
HttpPacket* HttpProxy::process_ssl_request()
{
    HttpPacket *packet = HttpPacket::create();
    std::string line;
    std::string request;

    if (!packet->packet_read_in(_client))
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_ssl_request_fail;
    }
 
    logger.message(logger.DEBUG,"Processing ssl request %s",packet->headline_get().c_str());

    packet->hostname_set(_target_host.c_str());
    
    packet->log();	

    packet->packet_write_out(_server);
    _server->write_flush();
    
    change_state(PROXY_EXPECT_SSL_RESPONSE);
    
    packet->source_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->source_set_port(socket_get_peer_port(_client->get_fd()));
    packet->destination_set_ip(socket_get_peer_ip(_server->get_fd()));
    packet->destination_set_port(socket_get_peer_port(_server->get_fd()));

    if (_last_request)
	delete _last_request;
    _last_request = packet;

    return _last_request;
    
process_ssl_request_fail:
    if (packet) delete packet;
    return NULL;
}

//
// PROXY_EXPECT_REQUEST
//
HttpPacket* HttpProxy::process_request()
{
    HttpPacket *packet = HttpPacket::create();
    std::string http_method;
    std::string http_ressource;
    std::string http_proto;
    std::string http_host;
    std::string http_path;

    if (!packet->packet_read_in(_client))
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_request_fail;
    }

    logger.message(logger.DEBUG,"Processing request %s",packet->headline_get().c_str());

    http_method    = packet->headline_get_part(0);
    http_ressource = packet->headline_get_part(1);
    http_proto	   = packet->headline_get_part(2);

    packet->log();	
    
    if (http_method=="CONNECT") /* assume SSL */
    {
	packet->source_set_ip(socket_get_peer_ip(_client->get_fd()));
	packet->source_set_port(socket_get_peer_port(_client->get_fd()));
	packet->destination_set_ip(socket_get_local_ip(_client->get_fd()));
	packet->destination_set_port(socket_get_local_port(_client->get_fd()));
	packet->hostname_set("[proxy]");

	if (_last_request)
	    delete _last_request;
	_last_request = packet;
	change_state(PROXY_EXPECT_TUNNEL);
	return _last_request;	
    }
     
    parse_url(http_ressource,http_host,http_path);
    packet->headline_set(http_method,http_path,http_proto);
    logger.message(logger.DEBUG,"Translated request to %s",packet->headline_get().c_str());

    packet->header_field_erase("Proxy-Connection");
    packet->header_field_set("Connection","close");

    if (_server==NULL) {
	if (!_secondary_proxy)
	{
	    int sock;
	    std::string host;

	    if (!packet->header_field_get("Host",host)) 
	    {
		logger.message(logger.ERROR,"Missing host header in message");
		change_state(PROXY_EXPECT_ERROR);
		goto process_request_fail;
	    }
	    _target_host = host;
    	    packet->hostname_set(host.c_str());

	    sock = tcp_connect(host.c_str());
	    
	    if (sock<0) 
	    {
		logger.message(logger.ERROR,"Failed to establish connection to %s",host.c_str());
		change_state(PROXY_EXPECT_RESPONSE_GATEWAY_TIMEOUT);
		goto process_request_fail;
	    }
	    
	    logger.message(logger.DEBUG,"established connection to %s",host.c_str());
	    _server = BufferInOutFile::create(sock);
	}
	else
	{
	    int sock;
	    std::string host;

	    if (!packet->header_field_get("Host",host)) 
	    {
		logger.message(logger.ERROR,"Missing host header in message");
		change_state(PROXY_EXPECT_ERROR);
		goto process_request_fail;
	    }
	    _target_host = host;
    	    packet->hostname_set(host.c_str());

	    sock = tcp_connect(_secondary_proxy_name.c_str());
	    if (sock<0) 
	    {
		change_state(PROXY_EXPECT_ERROR);
		goto process_request_fail;
	    }
	    logger.message(logger.DEBUG,"Established connection to secondary proxy %s",_secondary_proxy_name.c_str());
	    _server = BufferInOutFile::create(sock);
	}
    }	

    packet->packet_write_out(_server);
    _server->write_flush();

    packet->source_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->source_set_port(socket_get_peer_port(_client->get_fd()));
    packet->destination_set_ip(socket_get_peer_ip(_server->get_fd()));
    packet->destination_set_port(socket_get_peer_port(_server->get_fd()));

    change_state(PROXY_EXPECT_RESPONSE);
    if (_last_request)
	delete _last_request;
    _last_request = packet;
    return _last_request;

process_request_fail:
    if (packet) delete packet;
    return NULL;
}

//
// PROXY_EXPECT_SSL_RESPONSE
//
HttpPacket *HttpProxy::process_ssl_response()
{
    HttpPacket *packet = HttpPacket::create();

    if (!packet->packet_read_in(_server))
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_ssl_fail;
    }

    if (packet->headline_get().find("HTTP")!=0)
    {	
	logger.message(logger.ERROR,"Malformed SSL response header: %s",packet->headline_get().c_str());
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_ssl_fail;
    }
    
    logger.message(logger.DEBUG,"Processing SSL response %s",packet->headline_get().c_str());

    packet->hostname_set(_last_request->hostname_get());

    packet->log();

    if (!packet->packet_write_out(_client))
    {
	logger.message(logger.ERROR,"Failed to write SSL response packet to client");
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_ssl_fail; 
    }

    if (!_client->write_flush())
    {
	logger.message(logger.ERROR,"Failed to send SSL response packet to client");
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_ssl_fail; 
    }

    //change_state(PROXY_EXPECT_SSL_REQUEST);
    change_state(PROXY_EXPECT_CONNECTION_CLOSE);

    packet->hostname_set(_target_host.c_str());
    packet->source_set_ip(socket_get_peer_ip(_server->get_fd()));
    packet->source_set_port(socket_get_peer_port(_server->get_fd()));
    packet->destination_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->destination_set_port(socket_get_peer_port(_client->get_fd()));

    if (_last_response)
	delete _last_response;
    _last_response = packet;
    return _last_response;
process_response_ssl_fail:
    if (packet) delete packet;
    return NULL;
}

//
// PROXY_EXPECT_RESPONSE
//
HttpPacket* HttpProxy::process_response()
{
    HttpPacket *packet = HttpPacket::create();

    if (!packet->packet_read_in(_server))
    {
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_fail;
    }

    if (packet->headline_get().find("HTTP")!=0)
    {	
	logger.message(logger.ERROR,"Malformed response header: %s",packet->headline_get().c_str());
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_fail;
    }

    logger.message(logger.DEBUG,"Processing response %s",packet->headline_get().c_str());

    packet->header_field_set("Connection","close");
  
    packet->log();	

    if (!packet->packet_write_out(_client) || !_client->write_flush())
    {
	logger.message(logger.ERROR,"Failed to send response packet to client");
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_fail;
    }
    logger.message(logger.DEBUG,"Response sent back to client");

    change_state(PROXY_EXPECT_CONNECTION_CLOSE);
    
    packet->hostname_set(_target_host.c_str());
    packet->source_set_ip(socket_get_peer_ip(_server->get_fd()));
    packet->source_set_port(socket_get_peer_port(_server->get_fd()));
    packet->destination_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->destination_set_port(socket_get_peer_port(_client->get_fd()));

    if (_last_response)
	delete _last_response;
    _last_response = packet;
    return _last_response;

process_response_fail:
    if (packet) delete packet;
    return NULL;
}

//
// PROXY_EXPECT_RESPONSE_GATEWAY_TIMEOUT
//
HttpPacket* HttpProxy::process_response_gateway_timeout()
{
    HttpPacket *packet = HttpPacket::create();

    packet->headline_set("HTTP/1.1 504 Gateway timeout\r\n");
    packet->header_field_add("Proxy-agent: Proxy Certs\r\n");
    packet->header_field_add("Connection: close\r\n");
    packet->header_field_add("\r\n");
    packet->packet_write_out(_client);
    _client->write_flush();

    logger.message(logger.DEBUG,"Sending response %s",packet->headline_get().c_str());

    
    packet->log();	

    if (!packet->packet_write_out(_client) || !_client->write_flush())
    {
	logger.message(logger.ERROR,"Failed to send response packet to client");
	change_state(PROXY_EXPECT_ERROR);
	goto process_response_gateway_timeout_fail;
    }
    logger.message(logger.DEBUG,"Response sent back to client");

    change_state(PROXY_EXPECT_CONNECTION_CLOSE);
  
    packet->hostname_set("[proxy]");
    packet->destination_set_ip(socket_get_local_ip(_server->get_fd()));
    packet->destination_set_port(socket_get_local_port(_server->get_fd()));
    packet->source_set_ip(socket_get_peer_ip(_client->get_fd()));
    packet->source_set_port(socket_get_peer_port(_client->get_fd()));

if (_last_response)
	delete _last_response;
    _last_response = packet;
    return _last_response;

process_response_gateway_timeout_fail:
    if (packet) delete packet;
    return NULL;
}



bool HttpProxy::run()
{
    HttpPacket *packet = NULL;
    HttpPacketDB db;
    bool running = true;
    int packetid = -1;

    if (_client==NULL)
	return false;

    if (!_secondary_proxy)
	logger.message(logger.DEBUG,"Running proxy with direct connection");
    else
	logger.message(logger.DEBUG,"Running proxy with secondary proxy %s", _secondary_proxy_name.c_str());


    while (running) 
    {
	switch (_proxy_state) {
	    case PROXY_EXPECT_INIT:
	    case PROXY_EXPECT_REQUEST:
		packet = process_request();
		break;
	    case PROXY_EXPECT_RESPONSE:
		packet = process_response();
		break;
	    case PROXY_EXPECT_RESPONSE_GATEWAY_TIMEOUT:
		packet = process_response_gateway_timeout();
		break;
	    case PROXY_EXPECT_TUNNEL:
		packet = process_tunnel_setup();
		break;
	    case PROXY_EXPECT_SSL_INIT:
	    case PROXY_EXPECT_SSL_REQUEST:
		packet = process_ssl_request();
		break;
	    case PROXY_EXPECT_SSL_RESPONSE:
		packet = process_ssl_response();
		break;
	    case PROXY_EXPECT_CONNECTION_CLOSE:
	    case PROXY_EXPECT_ERROR:
		running = false;
		packet = NULL;
		break;
	}
	if (packet)
	{
	    db.open(false);
	    db.store(packet,packetid);
	    db.close();
	    packetid = packet->id_get()+1;
	}
	//if (_client->read_end() || _server->read_end()) break;
    }

    if (_proxy_state==PROXY_EXPECT_CONNECTION_CLOSE)
	logger.message(logger.DEBUG,"Connection ended through 'Connection: close' header");
    else if (_client->read_end())
	logger.message(logger.DEBUG,"Connection ended by client");
    else if (_server->read_end())
	logger.message(logger.DEBUG,"Connection ended by server");
    else
	logger.message(logger.DEBUG,"Connection ended because of error");
	    
//    return _client->eof() || _client->eof() || _connection_close;
    return true;
}

bool HttpProxy::set_secondary_proxy(const std::string &proxy_name)
{
    if (!proxy_name.empty())
    {
	_secondary_proxy_name = proxy_name;
	_secondary_proxy = true;
    }
    else
    {
	_secondary_proxy_name = "";
	_secondary_proxy = false;
    }
    return true;
}


/************************/
#include <sys/signal.h>
#include <sys/wait.h>

int PROCESS_COUNT=0;

void reaper(int sig)
{
    int status;

    while (wait3(&status,WNOHANG,(struct rusage *)0)>0)
    {
	PROCESS_COUNT -- ;
    }
}

void interupter(int sig)
{
    logger.message(logger.WARNING,"Caught SIGINT... stopping");
    fclose(stderr);
    fclose(stdout);
    exit(0);
}

void sigsegv_handler(int sig)
{
    logger.message(logger.ERROR,"ALERT! Caught SIGSEGV... stopping");
    fclose(stderr);
    fclose(stdout);
    exit(0);
}


int main(int argc, char **argv)
{
    int sock;
    int s;
    HttpProxy *proxy;
    char ip[20];
    int opt;
    int o_port = 9999;
    char *o_extra_proxy = NULL;

    while ((opt=getopt(argc,argv,"hp:x:VS")) != -1)
    {
	switch (opt) {
		case 'p':
		    o_port = atoi(optarg); /* TODO: check val. */
		    break;
		case 'x':
		    o_extra_proxy = optarg;
		    break;
		case 'V':
		    fprintf(stderr, VERSION_ID "\n");
		    exit(0);
		    break;
		case 'S':
		    openssl_save_cert = 1;
		    break;
		case 'h':
		default:
		    fprintf(stderr,"This tool is (c) Alain Pannetrat, licenced under the GPL version 3.\n\n");
		    fprintf(stderr,"usage: proxy [-p port] [-x extra_proxy_host:extra_proxy_port]\n");
		    fprintf(stderr,"       default port is 9999.\n\n");
		    exit(EXIT_FAILURE);
	}
    }
    

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    sock = tcp_listen(o_port);
    if (sock<0) exit(0);
    logger.message(logger.DEBUG,"Started proxy version %s, listening on port 9999.",VERSION_ID);
    if (openssl_save_cert)
	    logger.message(logger.DEBUG,"Certificates will be saved in current directory (option -S)\n");
    if (o_extra_proxy)
	logger.message(logger.DEBUG,"Requests will be forwarded to secondary proxy %s",o_extra_proxy);

    signal(SIGINT,interupter);
    signal(SIGCHLD,reaper);
    signal(SIGSEGV,sigsegv_handler);

    for (;;)
    {
	while (PROCESS_COUNT<5)
	{
	    int fval = fork();

	    switch (fval) {
		case 0:
		    s = tcp_accept(sock,ip);
		    close(sock);
		    proxy = HttpProxy::create(s);
		    if (o_extra_proxy)
			proxy->set_secondary_proxy(o_extra_proxy);  
		    proxy->run();
		    delete proxy;
		    close(s);
		    logger.message(logger.DEBUG,"Exiting.");
		    exit(0);
		default:
		    PROCESS_COUNT++;
		    logger.message(logger.DEBUG,"Spawned child process (pid=%i, process_count=%i)\n",
				   fval,PROCESS_COUNT);
		    break;
		case -1:
		    logger.message(logger.ERROR,"fork() failed, leaving the ship");
		    exit(1);
	    }
	}
	sleep(1);
    }
}

