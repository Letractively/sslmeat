
all:			client_cert.pem

client_cert.cst:	client_key_pair.key
			openssl.exe req -new -key client_key_pair.key -passin pass:secret -subj "/C=FR/O=Proxy Certs/CN=Proxy Certs Client" -out client_cert.csr

client_cert.pem:	client_cert.cst openssl.conf
			openssl.exe x509 -req -days 365 -in client_cert.csr -CA ca_cert.pem -CAkey ca_key_pair.key -passin pass:secret -set_serial 01 -extfile openssl.conf -out client_cert.pem
