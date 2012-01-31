
CXXFLAGS=-Wall -Wno-write-strings -pedantic -g -DVERSION_ID='"$(VERSION_ID)"'

LDFLAGS=-lcrypto -lssl -lsqlite3 -lz

OBJECTS = misc.o bufio.o tcp.o log_facility.o bufio_ssl.o bufio_zlib.o ssl_tools.o http_packet.o

all:
		@echo $$((`cat BUILD`+1)) > BUILD		
		make VERSION_ID=`cat VERSION`-`cat BUILD` proxy showp

proxy:		proxy.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o proxy proxy.cc $(OBJECTS) $(LDFLAGS)

showp:		showp.cc $(OBJECTS)
		$(CXX) $(CXXFLAGS) -o showp showp.cc $(OBJECTS) $(LDFLAGS)

dist:
		make VERSION_ID=`cat VERSION`-`cat BUILD` dist-tgz

dist-tgz:
		(cd ..; tar --exclude-vcs --exclude-backups --exclude='*.out' --exclude='*.db' -z -c -v -f sslmeat-$(VERSION_ID).tgz sslmeat/)
		@echo "-----------------------"
		@echo "created sslmeat-$(VERSION_ID).tgz"

clean:
	rm -f $(OBJECTS) *~ proxy showp *.stackdump *.exe
