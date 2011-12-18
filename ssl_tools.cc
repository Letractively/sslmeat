#include "ssl_tools.h"
#include "log_facility.h"

int openssl_save_cert=0;
#define GOOD_CHARS "abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-"

void X509_save(X509 *x, bool is_original)
	// used for debug
{
	char fname[128];
	char sname[128];
	char *cname;
	FILE *f;
	int i;

	X509_NAME_oneline(X509_get_subject_name(x), sname, 128);

	for (i=0;sname[i]!=0 && i<128;i++)
		if (!strchr(GOOD_CHARS,sname[i])) sname[i]='_';
	
	cname = strstr(sname,"CN_");

	if (cname)
		cname+=3;
	else
		cname=sname;

	if (is_original)
		sprintf(fname,"cert-%s-org.pem",cname);
	else
		sprintf(fname,"cert-%s-mod.pem",cname);
	if ((f=fopen(fname,"wb"))!=NULL)
	{
	    logger.message(logger.DEBUG,"Saving certificate in %s",fname);
	    PEM_write_X509(f,x);
	    fclose(f);
	}
	else
	    logger.message(logger.WARNING,"FAILED saving certificate in %s: %s",fname,strerror(errno));
}

X509* openssl_transform_certificate(X509 *src_cert, EVP_PKEY* cakey, EVP_PKEY* pubkey)
{
  X509 *dst_cert;
  X509_NAME *xname;
  long xversion;
  ASN1_INTEGER* xserial;
  ASN1_UTCTIME *xtime;
  const EVP_MD   *digest;
  X509_EXTENSION           *ext;
  int                       src_ext_pos;

  if (openssl_save_cert)
  	X509_save(src_cert,true);

  dst_cert = X509_new();

  xversion = X509_get_version(src_cert);
  X509_set_version(dst_cert,xversion);

  xserial = X509_get_serialNumber(src_cert);
  X509_set_serialNumber(dst_cert,xserial);

  xname = X509_NAME_new();
  X509_NAME_add_entry_by_txt(xname, "C", MBSTRING_ASC, (unsigned char *)"FR", -1, -1, 0);
  X509_NAME_add_entry_by_txt(xname, "ST", MBSTRING_ASC, (unsigned char *)"France", -1, -1, 0);
  X509_NAME_add_entry_by_txt(xname, "O", MBSTRING_ASC, (unsigned char *)"Proxy Certs", -1, -1, 0);
  X509_NAME_add_entry_by_txt(xname, "CN", MBSTRING_ASC, (unsigned char *)"Proxy Certs Master", -1, -1, 0);
  X509_set_issuer_name(dst_cert,xname);
  X509_NAME_free(xname);

  xtime = X509_get_notBefore(src_cert);
  X509_set_notBefore(dst_cert,xtime);

  xtime = X509_get_notAfter(src_cert);
  X509_set_notAfter(dst_cert,xtime);

  xname = X509_get_subject_name(src_cert);
  X509_set_subject_name(dst_cert,xname);

  X509_set_pubkey(dst_cert,pubkey);

  src_ext_pos = X509_get_ext_by_NID(src_cert,OBJ_sn2nid("subjectAltName"), -1);
  if (src_ext_pos >= 0)
  {
    ext = X509_get_ext(src_cert, src_ext_pos);
    X509_add_ext(dst_cert,ext,-1);
  }
  src_ext_pos = X509_get_ext_by_NID(src_cert,OBJ_sn2nid("keyUsage"), -1);
  if (src_ext_pos >= 0)
  {
    ext = X509_get_ext(src_cert, src_ext_pos);
    X509_add_ext(dst_cert,ext,-1);
  }
  src_ext_pos = X509_get_ext_by_NID(src_cert,OBJ_sn2nid("basicConstraints"), -1);
  if (src_ext_pos >= 0)
  {
    ext = X509_get_ext(src_cert, src_ext_pos);
    X509_add_ext(dst_cert,ext,-1);
  }
  src_ext_pos = X509_get_ext_by_NID(src_cert,OBJ_sn2nid("extendedKeyUsage"), -1);
  if (src_ext_pos >= 0)
  {
    ext = X509_get_ext(src_cert, src_ext_pos);
    X509_add_ext(dst_cert,ext,-1);
  }

  digest = EVP_sha1();
  if (!X509_sign(dst_cert,cakey,digest))
  {
	logger.message(logger.ERROR,"failed to sign with CA key\n");
        logger.message(logger.WARNING,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
        return 0;
  }
  
  logger.message(logger.DEBUG,"created new certificate\n");

  if (openssl_save_cert)
	X509_save(dst_cert,false);

  return dst_cert;
}

X509* openssl_load_cert_from_file(const char* certfile)
{
  FILE* SRC = fopen(certfile,"rb");
  X509* res = NULL;

  if (SRC==NULL)
  {
	logger.message(logger.ERROR,"Failed to open certificate file %s",certfile);
	return NULL;
  }

  res = PEM_read_X509(SRC,NULL,NULL,NULL);
  fclose(SRC);
  if (res==NULL)
  {
	logger.message(logger.ERROR,"Failed to read certificate from file %s",certfile);
	logger.message(logger.WARNING,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
	return NULL;
  }
  return res;
}

EVP_PKEY* openssl_load_private_key_from_file(const char* keyfile, const char *password)
{
  FILE* KF;
  EVP_PKEY* ret;

  if ((KF = fopen(keyfile,"rb"))==NULL)
  {
	logger.message(logger.ERROR,"Failed to open key file %s",keyfile);
	return NULL;
  }
  ret = PEM_read_PrivateKey(KF,NULL,NULL,(void *)password);
  fclose(KF);
  if (ret==NULL)
  {
	logger.message(logger.ERROR,"Failed to read key from file %s",keyfile);
	logger.message(logger.WARNING,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
	return NULL;
  }
  return ret;
}

DH* openssl_load_diffie_hellman_key_from_file(const char* keyfile)
{
	FILE* KF;
	DH* ret;

  if ((KF = fopen(keyfile,"rb"))==NULL)
  {
	logger.message(logger.ERROR,"Failed to open DH key file %s",keyfile);
	return NULL;
  }
  ret = PEM_read_DHparams(KF,NULL,NULL,NULL);
  fclose(KF);
  if (ret==NULL)
  {
	logger.message(logger.ERROR,"Failed to read DH key from file %s",keyfile);
	logger.message(logger.WARNING,"openssl error - %s\n",ERR_error_string(ERR_get_error(),NULL));
	return NULL;
  }
  return ret;
}


