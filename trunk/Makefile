
CXXFLAGS=-Wall -Wno-write-strings -pedantic -g

LDFLAGS=-lcrypto -lssl -lsqlite3 -lz

OBJECTS = misc.o bufio.o tcp.o log_facility.o bufio_ssl.o bufio_zlib.o ssl_tools.o http_packet.o

all:		proxy showp

proxy:		proxy.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o proxy proxy.cc $(OBJECTS) $(LDFLAGS)

showp:		showp.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o showp showp.cc $(OBJECTS) $(LDFLAGS)

dist:
		echo $$((`cat BUILD`+1)) > BUILD
		(cd ..; tar zcvf sslmeat-`cat SSLMEAT/VERSION`.`cat SSLMEAT/BUILD`.tgz SSLMEAT) 

clean:
	rm -f $(OBJECTS) *~ proxy showp *.stackdump
