#include "bufio_ssl.h" 
#include "log_facility.h"
#include "ssl_tools.h"
#include <openssl/err.h>
#include <openssl/x509.h>

BufferInOutSSL::BufferInOutSSL(int filedes): BufferInOutFile(filedes),  _ssl_ctx(NULL), _ssl(NULL)
{
	/* empty */
}

BufferInOutSSL* BufferInOutSSL::create(
		int filedes, 
		bool is_server,
		EVP_PKEY *privkey,
		unsigned certlen,
		X509** certchain) 
{
  DH* dhkey;
  int rcode;
  BufferInOutSSL *ret = new BufferInOutSSL(filedes);

  if ((ret->_ssl_ctx = SSL_CTX_new(SSLv23_method()))==NULL)
  {
    logger.message(logger.ERROR,"Error creating SSL CTX");
    logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
    goto error_cleanup;
  }

  if (certlen && certchain)
  {
    unsigned i;

    if (SSL_CTX_use_certificate(ret->_ssl_ctx,certchain[0])!=1)
    {
      logger.message(logger.ERROR,"Error loading certificate in SSL CTX");
      logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
      goto error_cleanup;			
    }
    logger.message(logger.DEBUG,"Added main certificate to SSL CTX");

    char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
    for (i=1;i<certlen;i++) 
    {
      if (SSL_CTX_add_extra_chain_cert(ret->_ssl_ctx,certchain[i])!=1)
      {
	logger.message(logger.ERROR,"Error loading extra certificate number %u in SSL CTX",i);
	logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
	goto error_cleanup;			
      }	
      logger.message(logger.DEBUG,"Added extra certificate %i to SSL CTX",i);
    }
  }

  if (privkey) {
    if (SSL_CTX_use_PrivateKey(ret->_ssl_ctx,privkey)!=1)
    {
      logger.message(logger.ERROR,"Error loading private key in SSL CTX");
      logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
      goto error_cleanup;
    }
  }

  dhkey = openssl_load_diffie_hellman_key_from_file("KEYS/dh1024.pem");
  if (dhkey) {
    if (SSL_CTX_set_tmp_dh(ret->_ssl_ctx,dhkey)!=1)
    {
      logger.message(logger.ERROR,"Error loading DH key in SSL CTX");
      logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
      goto error_cleanup;
    }
  }

  if ((ret->_ssl = SSL_new(ret->_ssl_ctx))==NULL)
  {
    logger.message(logger.ERROR,"Error creating SSL structure from SSL CTX");
    logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
    goto error_cleanup;
  }
  if (SSL_set_fd(ret->_ssl,ret->_filedes)!=1)
  {
    logger.message(logger.ERROR,"Error tying SSL structure to file descriptor '%i'",ret->_filedes);
    logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
    goto error_cleanup;
  }
  if (is_server)
  {
    if ((rcode = SSL_accept(ret->_ssl))<=0)
    {
      logger.message(logger.ERROR,"Error creating SSL server accept");
      switch (SSL_get_error(ret->_ssl,rcode)) {
	case SSL_ERROR_NONE:
	  logger.message(logger.DEBUG,"No error, this is odd...");
	  break;
	case SSL_ERROR_WANT_READ:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_WANT_READ");
	  break;
	case SSL_ERROR_WANT_WRITE:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_WANT_WRITE");
	  break;
	case SSL_ERROR_WANT_CONNECT:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_WANT_CONNECT");
	  break;
	case SSL_ERROR_WANT_ACCEPT:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_WANT_ACCEPT");
	  break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_WANT_X509_LOOKUP");
	  break;
	case SSL_ERROR_SYSCALL:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_SYSCALL: %s",ERR_error_string(ERR_get_error(),NULL));
	  break;
	case SSL_ERROR_SSL:
	  logger.message(logger.DEBUG,"SSL Error reports SSL_ERROR_SSL: %s",ERR_error_string(ERR_get_error(),NULL));
	  break;
	default:
	  logger.message(logger.DEBUG,"SSL unknwon error");	
      }
      goto error_cleanup;
    }
  }
  else
  {
    if (SSL_connect(ret->_ssl)<0)
    {
      logger.message(logger.ERROR,"Error creating SSL client connect");
      logger.message(logger.DEBUG,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
      goto error_cleanup;
    }
  }
  return ret;
error_cleanup:
  if (ret->_ssl_ctx)
    SSL_CTX_free(ret->_ssl_ctx);
  delete ret;
  return NULL;
}

bool BufferInOutSSL::read_load()
{
    int ret;

    if (_eof) return false;

    _read_pos = 0;

    ret = SSL_read(_ssl,_read_buf,BUFIO_BUFLEN);

    switch (SSL_get_error(_ssl,ret))
    {
	case SSL_ERROR_NONE:
	    _read_size = (unsigned)ret;
	    return true;
	case SSL_ERROR_ZERO_RETURN:
	    logger.message(logger.DEBUG,"SSL_ERROR_ZERO_RETURN in io_read");
	    _eof = true;
	    return false;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	    return read_load();
	case SSL_ERROR_WANT_CONNECT:
	    logger.message(logger.DEBUG,"SSL_ERROR_WANT_CONNECT in read_load()");
	    break;
	case SSL_ERROR_WANT_ACCEPT:
	    logger.message(logger.DEBUG,"SSL_ERROR_WANT_ACCEPT in read_load()");
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    logger.message(logger.DEBUG,"SSL_ERROR_WANT_X509_LOOKUP in read_load()");
	    break;
	case SSL_ERROR_SYSCALL:
	    logger.message(logger.DEBUG,"SSL_ERROR_SYSCALL in read_load()");
	    break;
	case SSL_ERROR_SSL:
	    logger.message(logger.DEBUG,"SSL_ERROR_SSL in read_load()");
	    break;
	default:
	    logger.message(logger.DEBUG,"Unknown SSL_ERROR in read_load()");
    }

    logger.message(logger.ERROR,"openssl error in read_load() - %s",ERR_error_string(ERR_get_error(),NULL));
    _eof = true;
    return false;

}

bool BufferInOutSSL::write_flush()
{
	int ret; 

	if (_eof) return false;

	_write_size = 0;
	
	ret = SSL_write(_ssl,_write_buf,BUFIO_BUFLEN);
	
	switch (SSL_get_error(_ssl,ret))
	{
		case SSL_ERROR_NONE:
			return true;
		case SSL_ERROR_ZERO_RETURN:
			logger.message(logger.DEBUG,"SSL_ERROR_ZERO_RETURN in io_write");
			_eof = true;
			return false;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return write_flush();
	}

    logger.message(logger.ERROR,"openssl error in write_flush() - %s",ERR_error_string(ERR_get_error(),NULL));
    _eof = true;
    return false;
}

BufferInOutSSL::~BufferInOutSSL()
{
	if (_ssl) 
	{
		SSL_shutdown(_ssl);
		SSL_free(_ssl);
	}
	if (_ssl_ctx)
		SSL_CTX_free(_ssl_ctx);
}

