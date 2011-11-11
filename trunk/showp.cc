#include <time.h>
#include <stdio.h>
#include "http_packet.h"
#include "log_facility.h"
#include "bufio.h"
#include "bufio_zlib.h"

using namespace std;

#define ANSI_BOLD	"\033[1m"
#define ANSI_DIM	"\033[2m"
#define ANSI_RED	"\033[31m"
#define ANSI_GREEN	"\033[32m"
#define ANSI_YELLOW	"\033[33m"
#define ANSI_BLUE 	"\033[34m"
#define ANSI_MAGENTA 	"\033[35m"
#define ANSI_CYAN 	"\033[36m"
#define ANSI_WHITE 	"\033[37m"

#define ANSI_RESET	"\033[0m"


bool trim_crlf(std::string &s)
{
	unsigned pos = s.find_first_of("\r\n");
	if (pos!=s.npos)
	{
	   s.erase(pos,s.npos);
	   return true;
	}
	return false;
}

unsigned OPTIONS = 0;
#define OPT_COLOR    		(OPTIONS&1)
#define OPT_CONTENT_RAW 	(OPTIONS&2)
#define OPT_SKIP_HEADLINE 	(OPTIONS&4)
#define OPT_SKIP_HEADERS 	(OPTIONS&8)
#define OPT_SKIP_CONTENT 	(OPTIONS&16)
#define OPT_ADD_PACKET_ID	(OPTIONS&32)
#define OPT_INFLATE_CONTENT	(OPTIONS&64)
#define OPT_VERBOSE		(OPTIONS&128)
#define OPT_RAW_PACKET_INPUT	(OPTIONS&256)

char HEX[17]="0123456789abcdef";

bool display_packet_hex(BufferOutMemory *mem, int packetid)
{
	unsigned i,j,clen;
	char buf_hex[16*3+1];
	char buf_chr[16+1];
	const unsigned char *content;
       
	content = mem->get_data();
	clen = mem->get_size();

	for (i=0;i<(clen+15)/16;i++)
	{
	    memset(buf_hex,' ',16*3);
	    buf_hex[16*3]=0;
	    memset(buf_chr,' ',16);
	    buf_chr[16]=0;

	    for (j=0;j<16 && i*16+j<clen;j++)
	    {
		buf_hex[j*3]	= HEX[content[i*16+j]>>4];
		buf_hex[j*3+1]	= HEX[content[i*16+j]&0xF];

		if (content[i*16+j]>=32 && content[i*16+j]<127)
		    buf_chr[j]=content[i*16+j];
		else
		    buf_chr[j]='.';
	    }
	    if (OPT_ADD_PACKET_ID)
		printf("[%08i] ",packetid);

	    if (OPT_COLOR)
	    	printf("%06x: %s%s%s| %s\r\n",i*16,ANSI_BOLD,buf_hex,ANSI_RESET,buf_chr);
	    else
		printf("%06x: %s| %s\r\n",i*16,buf_hex,buf_chr);
	}
	if (clen) printf("\r\n");
	return true;
}

bool display_packet_header(BufferOutMemory *mem, int packetid)
{
    unsigned i;
    unsigned clen;
    const unsigned char *content;

    content = mem->get_data();
    clen = mem->get_size();

    if (OPT_ADD_PACKET_ID)
	printf("[%08i] ",packetid);

    if (OPT_COLOR)
	printf(ANSI_CYAN);

    for (i=0;i<clen;i++)
    {
	if (content[i]=='\n')
	{
		if (OPT_COLOR) printf(ANSI_RESET "\n"); 
		else printf("\n");
    		if (OPT_ADD_PACKET_ID && (i+1)!=clen) printf("[%08i] ",packetid);
		if (OPT_COLOR) printf(ANSI_CYAN);
	}
	else if (content[i]==':' && OPT_COLOR)
	{
		printf(":" ANSI_BOLD);
	}
	else
	    printf("%c",content[i]);
    }
    if (OPT_COLOR)
	printf(ANSI_RESET);

    return true;
}

bool display_packet(HttpPacket *packet)
{
    int packet_id;
    HttpPacket::Timestamp timestamp;
    const char *src_ip;
    unsigned src_port;
    const char *dst_ip;
    unsigned dst_port;
    string headline;
    string content_type;
    bool inflate_content;
    string host;
    string headline_type;
    BufferOutMemory *content;
    BufferOutMemory *headers;
    char time_buf[20];
    struct tm *time_info;

    headline = packet->headline_get();
    trim_crlf(headline);
    packet_id = packet->id_get(); 
    timestamp = packet->timestamp_get();
    src_ip = packet->source_get_ip();
    src_port = packet->source_get_port();
    dst_ip = packet->destination_get_ip();
    dst_port = packet->destination_get_port();

    time_info = localtime((const time_t *)&timestamp.ts_sec);
    strftime(time_buf,20,"%x,%X",time_info);

    if (headline[0]=='H')
        headline_type = packet->headline_get_part(1);
    else
	headline_type = packet->headline_get_part(0);

    if (packet->header_field_exists("Content-type"))
    	packet->header_field_get("Content-type",content_type);
    else
	content_type = "unknown type";

    inflate_content = ( ( packet->header_field_value_match("Content-encoding","gzip") ||
    		          packet->header_field_value_match("Content-encoding","deflate") ) &&
			OPT_INFLATE_CONTENT );

    if (packet->header_field_exists("Host"))
	packet->header_field_get("Host",host);
    else 
	host = "unknwon host";

    if (OPT_COLOR)
    {
	if (headline[0]=='H')
		printf(ANSI_RED ANSI_BOLD);
	else
		printf(ANSI_GREEN ANSI_BOLD);
    }

    if (!OPT_SKIP_HEADLINE)
    {
	printf("[%08i] %s,%06u %15s:%-5u %15s:%-5u %7s %-20s",
	       packet_id,
	       time_buf,
	       timestamp.ts_usec,
	       src_ip,
	       src_port,
	       dst_ip,
	       dst_port,
	       headline_type.c_str(),
	       packet->hostname_get());

	if (OPT_COLOR)
	    printf(ANSI_RESET "\r\n");
	else
	    printf("\r\n");
    }

    if (!OPT_SKIP_CONTENT)
    {
	if (inflate_content)
	{
	    content = BufferInflateMemory::create();
	    packet->content_write_out(content);
	    if (content->get_data()==NULL)
	    {
		delete(content);

		content = BufferOutMemory::create();
		packet->content_write_out(content);

		packet->header_field_add("X-Showp-Content-decoding: failed\r\n");
		logger.message("Failed to decompress data in packet %08u\n",packet_id);
	    }
	    else
	    {
		packet->header_field_erase("Content-encoding");
		packet->header_field_add("X-Showp-Content-decoding: success\r\n");
		packet->header_field_set("Content-length",content->get_size());
	    }
	}
	else
	{
	    content = BufferOutMemory::create();
	    packet->content_write_out(content);
	}
    }

    if (!OPT_SKIP_HEADERS)
    {
	headers = BufferOutMemory::create();
	packet->header_write_out(headers);
	display_packet_header(headers,packet_id);
	delete(headers);
    }

    if (!OPT_SKIP_CONTENT)
    {
	if (OPT_CONTENT_RAW)
	    fwrite(content->get_data(),content->get_size(),1,stdout);
	else
	    display_packet_hex(content,packet_id);
	delete(content);
    }

    return true;
}

int packetid = 0;
HttpPacket *load_packet(BufferInOutFile *bio)
{
	HttpPacket *r;
	string rheader;

	if (bio==NULL)
		return NULL;
	if (!bio->read_line(rheader))
		return NULL;
	r = HttpPacket::create();
	if (!r->headline_set(rheader) ||
	    !r->header_read_in(bio) ||
	    !r->content_read_in(bio))
	{
		delete r;
		return NULL;
	}
	r->id_set(packetid++);
	return r;
}

int main(int argc, char** argv)
{
    int opt;
    HttpPacketDB db;
    char *expr = NULL;

    while ((opt = getopt(argc, argv, "cbIHCnzvpe:h")) != -1) {
	switch (opt) {
	    case 'c':
		OPTIONS |= 1;	// color
		break;
	    case 'b':
		OPTIONS |= 2;	// raw binary content output of body
		break;
	    case 'I':
		OPTIONS |= 4;	// remove headline
		break;
	    case 'H':
		OPTIONS |= 8;	// remove headers
		break;
	    case 'C':
		OPTIONS |= 16;	// remove content
		break;
	    case 'n':
		OPTIONS |= 32;	// number each line
		break;
	    case 'z':
		OPTIONS |= 64; 	// gunzip content
		break;
	    case 'v':
		OPTIONS |= 128; // verbose (not used now)
		break;
	    case 'p':
		OPTIONS |= 256;	// get packet from stdin
		break;
	    case 'e':
		expr = optarg;	// select packets according to expression
		break;
            case 'h':
	    default: /* '?' */
		fprintf(stderr, 
			"Usage: %s [-c] [-b] [-I] [-H] [-C] [-n] [-z] [-p] [-e expression]\n"
			"	-c:	color output\n"
			"	-b:	output raw binary packet body\n"
			"	-I:	remove packet descriptor from output\n"
			"	-H:	remove packet headers from output\n"
			"	-C:	remove packet content from output\n"
			"	-n:	number each line with the packetid (except when -b is present)\n"
			"	-z:	inflate gzip-compressed content when possible\n"
			"	-p:	process packet from standard inpur instead of packets.db\n"
			"	-e: 	select packet matching expression (e.g. 'packetid > 256')\n",	
			argv[0]);
		exit(EXIT_FAILURE);
	}
    }

    if (OPT_RAW_PACKET_INPUT)
    {
	    HttpPacket *packet;
	    BufferInOutFile *bio;
	    bio = BufferInOutFile::create(STDIN_FILENO);

	    if (!OPT_VERBOSE) logger.hide(); 

	    while (!bio->read_end())
	    {
	    	packet = load_packet(bio);
	    	if (packet)
	    	{
		    display_packet(packet);
		    delete packet;
	    	}
	    	else
		    break;
	    }
	    logger.show();
	    delete bio;
    }
    else
    {
	    db.open(true);
	    if (!OPT_VERBOSE) logger.hide();
	    if (db.iterate(expr,display_packet)==false && expr)
	    {
		    fprintf(stderr,"Error processing request: check that '%s' is a correct expression.\n",expr);
		    db.close();
		    exit(-2);
	    }
	    logger.show();
	    db.close();
    }
}
