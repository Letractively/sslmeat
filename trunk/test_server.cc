#include "bufio_ssl.h"
#include "log_facility.h"
#include "tcp.h"
#include "ssl_tools.h"

static void sigpipe_handle(int x){
}

int main()
{
	bufio_ssl *buf;
	// bufio *buf;
	X509* local_server_cert;
	X509* local_ca_cert;
	EVP_PKEY* local_server_key;
	int sock;
	int s;
	char ip[20];
	X509 *cert_chain[2];
	std::string line;

	signal(SIGPIPE,sigpipe_handle);

	SSL_library_init();
	SSL_load_error_strings();
  	OpenSSL_add_all_algorithms();

	if ((local_server_key = openssl_load_private_key_from_file("KEYS/client_key_pair.key","secret"))==NULL)
		exit(0);
	if ((local_ca_cert = openssl_load_cert_from_file("KEYS/ca_cert.pem"))==NULL)
		exit(0);
	if ((local_server_cert = openssl_load_cert_from_file("KEYS/client_cert.pem"))==NULL)
		exit(0);
	logger.message("Loaded keys");

	sock = tcp_listen(443);
	if (sock<0)
		exit(0);
	logger.message("Satarted server");

	while ((s = tcp_accept(sock,ip))>=0)
	{
		logger.message("Got connection");

		cert_chain[0]=local_server_cert;
		cert_chain[2]=local_ca_cert;

		buf =  bufio_ssl::create(s, "dummy", true, local_server_key, 2, cert_chain);
		// buf =  bufio::create(s, "dummy");
		if (buf==NULL)
			exit(0);
		logger.message("Accepted SSL");

		while (buf->read_line(line))
		{
			logger.message("GOT: %s",line.c_str());
			if (line=="\r\n") {
				buf->write_line("HTTP/1.1 200 OK\r\nHost: localhost\r\nContent-length: 5\r\n\r\nHELLO\r\n");
				buf->flush();
				break;
			}
		}
		logger.message("Done");
	}
	exit(0);
}
