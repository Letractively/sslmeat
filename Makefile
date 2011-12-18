
CXXFLAGS=-Wall -Wno-write-strings -pedantic -g -DVERSION_ID='"$(VERSION_ID)"'

LDFLAGS=-lcrypto -lssl -lsqlite3 -lz

OBJECTS = misc.o bufio.o tcp.o log_facility.o bufio_ssl.o bufio_zlib.o ssl_tools.o http_packet.o

all:
		echo $$((`cat BUILD`+1)) > BUILD		
		make VERSION_ID=`cat VERSION`-`cat BUILD` proxy showp

proxy:		proxy.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o proxy proxy.cc $(OBJECTS) $(LDFLAGS)

showp:		showp.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o showp showp.cc $(OBJECTS) $(LDFLAGS)

dist:
		(cd ..; tar zcvf sslmeat-$(VERSION_ID).tgz SSLMEAT) 

clean:
	rm -f $(OBJECTS) *~ proxy showp *.stackdump
