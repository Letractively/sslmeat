#ifndef BUFIO_SSL_H
#define BUFIO_SSL_H

#include "bufio.h"
#include <openssl/ssl.h>

class BufferInOutSSL : public BufferInOutFile {
	public:
		static BufferInOutSSL* create(int filedes, 
				bool is_server,
				EVP_PKEY *privkey = NULL,
				unsigned certlen  = 0,
				X509 **certchain  = NULL ); /* named constructor */
		SSL* get_ssl() { return _ssl; }
		virtual bool read_load();
		virtual bool write_flush();
		virtual ~BufferInOutSSL();
	protected:
		BufferInOutSSL(int filedes = -1);

	private:		
		SSL_CTX* _ssl_ctx;
		SSL* _ssl;

		DISALLOW_COPY_AND_ASSIGN(BufferInOutSSL);
};

#endif
