#ifndef HTTP_PACKET_H
#define HTTP_PACKET_H

#include <vector>
#include <string>
#include "bufio.h"
#include "log_facility.h"
#include "misc.h"

class HttpPacket {
	public:
		typedef struct {
			unsigned ts_sec;
			unsigned ts_usec;
		} Timestamp;

		static HttpPacket* create();

		void id_set(int packet_id)		{ _packet_id = packet_id; }
		unsigned id_get() const 		{ return _packet_id; }

		void timestamp_set(const Timestamp &ts);
		const Timestamp &timestamp_get() const;

		void source_set_ip(const char *ip);
		void source_set_port(unsigned port);
		const char *source_get_ip() const;
		unsigned source_get_port() const;
		void hostname_set(const char *hostname) 	{ if (_host) free(_host); _host = strdup(hostname); }
		const char *hostname_get() const		{ return _host; }

		void destination_set_ip(const char *ip);
		void destination_set_port(unsigned port);
		const char *destination_get_ip() const;
		unsigned destination_get_port() const;


		bool headline_set(const std::string& s);
		bool headline_set(const std::string& part1, const std::string& part2, const std::string& part3) 
			{ return headline_set(part1 + " " + part2 + " " + part3 + "\r\n"); }
		const std::string& headline_get() const;
		const std::string& headline_get_part(int part) const;

		bool header_field_add(const std::string& s);
		bool header_field_erase(const std::string& s);
		bool header_field_exists(const std::string& s) const;
		bool header_field_set(const std::string& field, const std::string& value);
		bool header_field_set(const std::string& field, int value);
		bool header_field_get(const std::string& field, std::string& value) const;
		bool header_field_get(const std::string& field, int& value) const;
		bool header_field_value_match(const std::string& field, const std::string& word) const;

		bool header_read_in(BufferIn* in);
		bool header_write_out(BufferOut *out) const;

		bool content_read_in(BufferIn *in);
		bool content_add(unsigned len, const unsigned char *content);
		unsigned content_get_length() const;
		const unsigned char *content_get() const;
		bool content_write_out(BufferOut *out) const;

		bool packet_read_in(BufferIn *in);
		bool packet_write_out(BufferOut *out) const;

		void log() const;
		~HttpPacket();
	private:
		std::vector<std::string>::iterator header_field_search(const std::string& s);
		std::vector<std::string>::const_iterator header_field_search_const(const std::string& s) const;

		HttpPacket() : 
			_content(NULL), 
			_content_size(0), 
			_content_max(0), 
			_packet_id(-1),
			_host(NULL),
			_packet_source_port(0),
			_packet_destination_port(0)
    			{
			  _packet_timestamp.ts_sec	= 0;
			  _packet_timestamp.ts_usec 	= 0;
			  source_set_ip("undefined");
			  destination_set_ip("undefined");
			  hostname_set("undefined");
			}
		HttpPacket(const HttpPacket&);
		HttpPacket& operator=(const HttpPacket&);

		std::string _headline;
		std::string _headline_parts[3];

		std::vector<std::string> _headers;
		std::string _headers_terminator;

		unsigned char *_content;
		unsigned _content_size;
		unsigned _content_max;

		int	 _packet_id;
		char 	*_host;
		Timestamp _packet_timestamp;
		char	 _packet_source_ip[40]; /* 16 for ipv4, 40 for ipv6 */
		unsigned _packet_source_port;
		char 	 _packet_destination_ip[40];
		unsigned _packet_destination_port;

		static std::string _empty_string;
};

#include <sqlite3.h>
class HttpPacketDB {
	public:
		bool open(bool readonly);
		bool iterate(char *expression, bool(*iter_cb)(HttpPacket *));
		bool store(HttpPacket* packet, int packetid);
	        int top_id();
		void close();

		HttpPacketDB() : _dbhandle(NULL) {}
		~HttpPacketDB() { if (_dbhandle) close(); }
		static void set_file(const std::string& db) { _db_name = db; }
	private:
		static std::string _db_name;
		sqlite3* _dbhandle;
};

#endif
