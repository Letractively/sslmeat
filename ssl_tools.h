#ifndef SSL_TOOLS_H
#define SSL_TOOLS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

X509* openssl_transform_certificate(X509 *src_cert, EVP_PKEY* cakey, EVP_PKEY* pubkey);

X509* openssl_load_cert_from_file(const char* certfile);

EVP_PKEY* openssl_load_private_key_from_file(const char* keyfile, const char *password);

DH* openssl_load_diffie_hellman_key_from_file(const char* keyfile);

extern int openssl_save_cert;
#endif
