#include "http_packet.h"
#include <cerrno>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>

std::string HttpPacket::_empty_string = "";

/* static */ HttpPacket* HttpPacket::create()
{
	HttpPacket *packet = new HttpPacket();
	struct timeval tv;
	Timestamp ts;

	gettimeofday(&tv,NULL);
	ts.ts_sec = tv.tv_sec;
	ts.ts_usec = tv.tv_usec;
	packet->timestamp_set(ts);
	
	return packet;
}

void HttpPacket::timestamp_set(const Timestamp &ts)
{
	_packet_timestamp = ts;
}

const HttpPacket::Timestamp &HttpPacket::timestamp_get() const
{
	return _packet_timestamp;
}

void HttpPacket::source_set_ip(const char *ip)
{
  strlcpy(_packet_source_ip,ip,40);
}

void HttpPacket::source_set_port(unsigned port)
{
    _packet_source_port = port;
}

const char *HttpPacket::source_get_ip() const
{
    return _packet_source_ip;
}

unsigned HttpPacket::source_get_port() const
{
    return _packet_source_port;
}

void HttpPacket::destination_set_ip(const char *ip)
{
    strlcpy(_packet_destination_ip,ip,40);
}

void HttpPacket::destination_set_port(unsigned port)
{
    _packet_destination_port = port;
}

const char *HttpPacket::destination_get_ip() const
{
    return _packet_destination_ip;
}

unsigned HttpPacket::destination_get_port() const
{
    return _packet_destination_port;
}

bool HttpPacket::headline_set(const std::string& s)
{
    unsigned start, end;

    start = s.find(' ');
    if (start == std::string::npos || start == 0)
	return false;
    _headline_parts[0].assign(s,0,start);

    start++;
    while (s[start]==' ') start++;

    end = s.find(' ',start);
    if (end == std::string::npos || end == start)
	return false;
    _headline_parts[1].assign(s,start,end-start);

    start = end + 1;
    while (s[start]==' ') start++;

    end = s.find_first_of("\r\n",start);
    if (end == std::string::npos || end == start)
	return false;
    _headline_parts[2].assign(s,start,end-start);

    _headline = s;

    return true;
}

const std::string& HttpPacket::headline_get() const
{
	return _headline;
}

const std::string& HttpPacket::headline_get_part(int part) const
{
	if (_headline.empty() || part<0 || part>2)
	  return _empty_string;
	return _headline_parts[part];
}

bool HttpPacket::header_field_add(const std::string& s)
{
  if (s=="\r\n" || s=="\n")
  {
    _headers_terminator = s;
    return false;
  }

  if ((s[0]==' ' || s[0]=='\t') && !_headers.empty())
  {
    _headers.back() += s;
  }
  else
  {
    _headers.push_back(s);
  }
  return true;
}

bool HttpPacket::header_field_erase(const std::string& s)
{
        std::vector<std::string>::iterator iter = header_field_search(s);
        if (iter==_headers.end())
                  return false;
        _headers.erase(iter);
        return true;
}

bool HttpPacket::header_field_exists(const std::string& s) const
{
        std::vector<std::string>::const_iterator iter = header_field_search_const(s);
        if (iter==_headers.end())
                  return false;
        return true;
}

bool HttpPacket::header_field_set(const std::string& field, const std::string& value)
{
  std::string header;
  std::vector<std::string>::iterator iter;

  header = field;
  header += ": ";
  header += value;
  header += "\r\n";
  iter = header_field_search(field);
  if (iter!=_headers.end()) 
    (*iter) = header;
  else 
    _headers.push_back(header);
  return true;
}

bool HttpPacket::header_field_set(const std::string& field, int value)
{
  char buf[16];
  sprintf(buf,"%i",value);
  return header_field_set(field,buf);
} 

bool HttpPacket::header_field_get(const std::string& field, std::string& value) const
{
  char c;
  unsigned i;
  std::vector<std::string>::const_iterator iter = header_field_search_const(field);
  
  value = "";
  if (iter==_headers.end())
    return false;

  i=(*iter).find(':')+1;
  while ((*iter).at(i)<=' ' && i<(*iter).size()) i++;
  while (i<(*iter).size())
  {
    c = (*iter).at(i);
    switch (c) {
      case '\n':
      case '\r':
	break;
      case '\t':
	value += ' ';
	break;
      default: 
	value += c;
    }
    i++;
  }
  return true;
}

bool HttpPacket::header_field_get(const std::string& field, int& value) const
{
    std::string str_value;
    if (header_field_get(field,str_value)==false)
	return false;
    value = atoi(str_value.c_str());
    return true;
}

bool HttpPacket::header_field_value_match(const std::string& field, const std::string& word) const
{
  unsigned pos,pos_next;
  char c;
  std::vector<std::string>::const_iterator iter = header_field_search_const(field);
  if (iter==_headers.end())
    return false;

  pos = (*iter).find(word,(*iter).find(':')+1);
  if (pos==std::string::npos) return false;
  pos_next = pos + word.size();
  c = (*iter).at(pos_next);
  if (c!=',' && c!=';' && c!=':' && c>32) return false;
  c = (*iter).at(pos-1);
  if (c!=',' && c!=';' && c!=':' && c>32) return false;
  return true;
}

bool HttpPacket::header_read_in(BufferIn *in)
{
    std::string line;
    if (in->read_line(line)==false)
	return false;
    headline_set(line);

    while (in->read_line(line))
    {
	if (header_field_add(line)==false)
	{
	    logger.message(logger.DEBUG,"Http header was loaded");
	    return true; /* we got to the final '\r\n' */
	}
    }
    logger.message(logger.WARNING,"Failed to load http header");
    return false;
}

bool HttpPacket::header_write_out(BufferOut *out) const
{
  std::vector<std::string>::const_iterator iter;

  out->write_line(_headline);
  for (iter=_headers.begin();iter!=_headers.end();iter++)
  {
    out->write_line(*iter);
  }
  return out->write_line(_headers_terminator);
}

#define CONTENT_BLOCK_LENGTH 8192
bool HttpPacket::content_read_in(BufferIn *in)
{
    unsigned char buf[CONTENT_BLOCK_LENGTH];
    unsigned content_length;
    unsigned content_length_total;
    unsigned chunk_length;
    unsigned rlen;
    std::string line;

    if (header_field_get("Content-length",(int&)content_length))
    {
	content_length_total = content_length;

	while (content_length)
	{
	    rlen = content_length<CONTENT_BLOCK_LENGTH?content_length:CONTENT_BLOCK_LENGTH;
	    if (!in->read_block(rlen,buf))
	    {
		logger.message(logger.WARNING,"Failed to read content from source (with %u bytes remaining)",content_length);
		return false;
	    }
	    content_add(rlen,buf);
	    content_length-=rlen;
	}
	logger.message(logger.DEBUG,"Read a total of %u bytes of content based on the 'Content-length' header",content_length_total);
	return true;
    }
    else if (header_field_value_match("Transfer-encoding","chunked"))
    {
	content_length_total = 0;
	
	while (in->read_line(line))
	{
	    chunk_length = content_length = (unsigned)strtol(line.c_str(),NULL,16);
	    
	    //logger.message("CHUNK %s",line.c_str());
	    //content_add(line.size(),(unsigned char *)line.data());

	    while (content_length)
	    {
		rlen = content_length<CONTENT_BLOCK_LENGTH?content_length:CONTENT_BLOCK_LENGTH;
		if (!in->read_block(rlen,buf))
		{
		    logger.message(logger.WARNING,"Failed to read content from source (with %u bytes remaining in chunk)",content_length);
		    return false;
		}
		content_add(rlen,buf);
		content_length       -= rlen;
		content_length_total += rlen;
	    }
	    in->read_line(line);
	    //content_add(line.size(),(unsigned char *)line.data());
	    
	    if (line!="\r\n" && line!="\n")
	    {
		logger.message(logger.WARNING,"Block does not end with CRLF in chunked encoding, aborting content loading.");
		break;
	    }

	    if (chunk_length==0) break;
	}
	header_field_erase("Transfer-encoding");
	header_field_set("Content-length",content_length_total);

	logger.message(logger.DEBUG,"Read a total of %u bytes of content in chucked encoding",content_length_total);
	return true;
    }
    else if (header_field_exists("Content-type") && _headline_parts[1]=="200")
    {
	content_length_total = 0;

	logger.message(logger.DEBUG,"No content-length or chunked encoding, but content-type is defined, processing response.");
	do {
	    rlen = 8192;
	    logger.message(logger.DEBUG,"Read attempt");
	    if (!in->read_block(rlen,buf)) break;
	    logger.message(logger.DEBUG,"Got %i bytes",rlen);
	    content_add(rlen,buf);
	    content_length_total += rlen;
	}
	while (rlen==8192);
	logger.message(logger.DEBUG,"Read a total of %u bytes of content until end of file",content_length_total);
	return true;
    }
    
    logger.message(logger.DEBUG,"No content detected");
    return true;
}

bool HttpPacket::content_add(unsigned len, const unsigned char *content)
{
  unsigned char *odata;

  if (len==0)
    return true;
  if (_content==NULL)
  {
    _content_max = (len<8?8:len);
    _content = new unsigned char[_content_max];
    if (_content==NULL) return false;
  }
  else if (_content_max-_content_size<len)
  {
    while ((_content_max-_content_size)<len) _content_max<<=1;
    odata = new unsigned char[_content_max];
    if (_content==NULL) return false;
    memcpy(odata,_content,_content_size);
    delete [] _content;
    _content = odata;
  }
  memcpy(_content+_content_size,content,len);
  _content_size+=len;
  return true;

}

unsigned HttpPacket::content_get_length() const
{
  return _content_size;
}

const unsigned char *HttpPacket::content_get() const
{
  return _content;
}

bool HttpPacket::content_write_out(BufferOut *out) const
{
    unsigned content_size = _content_size;
    return out->write_block(content_size,_content);  
}

bool HttpPacket::packet_read_in(BufferIn *in)
{
    return header_read_in(in) && content_read_in(in);
}

bool HttpPacket::packet_write_out(BufferOut *out) const
{
  return header_write_out(out) && content_write_out(out);
}

void HttpPacket::log() const
{
  char buf[80];
  std::vector<std::string>::const_iterator iter;

  logger.message(logger.DEBUG,"http: - %s",_headline.c_str());
  for (iter=_headers.begin();iter!=_headers.end();iter++)
  {
      if ((*iter).size()<80)
      {
	memcpy(buf,(*iter).data(),(*iter).size());
	buf[(*iter).size()]=0;
      }
      else
      {
	memcpy(buf,(*iter).data(),74);
	memcpy(buf+74,"(...)",6);
      }
      logger.message(logger.DEBUG,"http: + %s",buf);
  }
  logger.message(logger.DEBUG,"http: ** %i bytes of content follow **",_content_size);  
}

HttpPacket::~HttpPacket()
{
  if (_content)
    delete [] _content;
}


/*private*/ std::vector<std::string>::iterator HttpPacket::header_field_search(const std::string& s)
{
  std::vector<std::string>::iterator iter;
  int i;

  for (iter=_headers.begin();iter!=_headers.end();iter++)
  {
    if ((*iter).find(':')==s.size())
    {
      i = 0;
      while (toupper((*iter).at(i))==toupper(s[i])) i++;
      if (s[i]==0) return iter;
    }
  }
  return _headers.end();
}

/*private*/ std::vector<std::string>::const_iterator HttpPacket::header_field_search_const(const std::string& s) const
{
  std::vector<std::string>::const_iterator iter;
  int i;

  for (iter=_headers.begin();iter!=_headers.end();iter++)
  {
    if ((*iter).find(':')==s.size())
    {
      i = 0;
      while (toupper((*iter).at(i))==toupper(s[i])) i++;
      if (s[i]==0) return iter;
    }
  }
  return _headers.end();
}

/************************************************************************************/

bool HttpPacketDB::open(bool readonly)
{
    const char *stmt = "CREATE TABLE packets ("
	    			"packetid INTEGER PRIMARY KEY,"
				"sec INTEGER,"
				"usec INTEGER,"
		        	"src_addr TEXT,"
			        "src_port INTEGER,"
			        "dst_addr TEXT,"
				"dst_port INTEGER,"
				"hostname TEXT,"
				"data BLOB );";
    char *errmsg;

    if (readonly)
    {
	if (sqlite3_open_v2(_db_name.c_str(),&_dbhandle,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK)
	{
	    sqlite3_busy_timeout(_dbhandle,1000);
	    return true;
	}
	logger.message(logger.ERROR,"Error opening %s read-only.",_db_name.c_str());
	return false;
    }
    
    if (sqlite3_open_v2(_db_name.c_str(),&_dbhandle,SQLITE_OPEN_READWRITE,NULL)==SQLITE_OK)
    {
	sqlite3_busy_timeout(_dbhandle,1000);
	return true;
    }	

    if (sqlite3_open_v2(_db_name.c_str(),&_dbhandle,SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)!=SQLITE_OK)
    {
	logger.message(logger.ERROR,"Error creating %s.",_db_name.c_str());
	close();
	return false;
    }
    sqlite3_busy_timeout(_dbhandle,1000);
    if (sqlite3_exec(_dbhandle,stmt,NULL,NULL,&errmsg)!=SQLITE_OK)
    {
	logger.message(logger.ERROR,"Error creating table in %s: %s",_db_name.c_str(),errmsg);
	sqlite3_free(errmsg);
	close();
	return false;
    }
    logger.message(logger.DEBUG,"Created SQL database %s",_db_name.c_str());
    return true;
}

int HttpPacketDB::top_id()
{
    int top_id;

    sqlite3_stmt *compiled_stmt;

    if (sqlite3_prepare_v2(_dbhandle,"SELECT MAX(packetid) FROM packets;",-1,&compiled_stmt,NULL)!=SQLITE_OK)
    {
	return 0;
    }
    if (sqlite3_step(compiled_stmt)!=SQLITE_ROW)
    {
	sqlite3_finalize(compiled_stmt);
	return 0;
    }
    top_id = sqlite3_column_int(compiled_stmt,0);
    sqlite3_finalize(compiled_stmt);
    return top_id;
}

bool HttpPacketDB::iterate(char *expression, bool(*iter_cb)(HttpPacket *))
{
    char *stmt;
    sqlite3_stmt *compiled_stmt;
    int packet_id;
    HttpPacket::Timestamp timestamp;
    const char *src_ip;
    unsigned src_port;
    const char *dst_ip;
    unsigned dst_port;
    const char *hostname;
    int err_code;
    bool ret_code;
    BufferInMemory *blob;
    HttpPacket *packet;
     
    if (expression)
    	stmt = sqlite3_mprintf("SELECT * FROM packets WHERE %s;",expression);
    else
	stmt = sqlite3_mprintf("SELECT * FROM packets;");

    if (sqlite3_prepare_v2(_dbhandle,stmt,-1,&compiled_stmt,NULL)!=SQLITE_OK)
    {
	logger.message(logger.ERROR,"Error creating SQL statement in %s: %s",
		       _db_name.c_str(),
		       sqlite3_errmsg(_dbhandle));
	sqlite3_free(stmt);
	return false;
    }
    sqlite3_free(stmt);

    for (;;)
    {
	err_code = sqlite3_step(compiled_stmt);
	if (err_code == SQLITE_DONE)
	{
	    ret_code = true;
	    break;
	}
	else if (err_code == SQLITE_ROW)
	{
	    packet_id = sqlite3_column_int(compiled_stmt,0);
	    timestamp.ts_sec = (unsigned)sqlite3_column_int(compiled_stmt,1);
	    timestamp.ts_usec = (unsigned)sqlite3_column_int(compiled_stmt,2);
	    src_ip = (const char *)sqlite3_column_text(compiled_stmt,3);
	    src_port = (unsigned)sqlite3_column_int(compiled_stmt,4);
	    dst_ip = (const char *)sqlite3_column_text(compiled_stmt,5);
	    dst_port = (unsigned)sqlite3_column_int(compiled_stmt,6);
	    hostname = (const char *)sqlite3_column_text(compiled_stmt,7);
	    blob = BufferInMemory::create((unsigned)sqlite3_column_bytes(compiled_stmt,8), 
					  (unsigned char *)sqlite3_column_blob(compiled_stmt,8));
	    packet = HttpPacket::create();
	    packet->id_set(packet_id);
	    packet->packet_read_in(blob);
	    packet->timestamp_set(timestamp);
	    packet->source_set_ip(src_ip);
	    packet->source_set_port(src_port);
	    packet->destination_set_ip(dst_ip);
	    packet->destination_set_port(dst_port);
	    packet->hostname_set(hostname);
	    iter_cb(packet);
	    delete packet;
	    delete blob;
	}
	else
	{
	    ret_code = false;
	    break;
	}
    }
    sqlite3_finalize(compiled_stmt);
    return ret_code;
}

bool HttpPacketDB::store(HttpPacket* packet, int packetid)
{
    char *stmt;
    sqlite3_stmt *compiled_stmt;
    HttpPacket::Timestamp timestamp;
    const char *src_ip;
    unsigned src_port;
    const char *dst_ip;
    const char *hostname;
    unsigned dst_port;
    BufferOutMemory *data;
    int i,err_code;

    if (_dbhandle==NULL)
	return false;

    if (packetid<0)
    {
	if (sqlite3_prepare_v2(_dbhandle,
			       "SELECT ifnull(((MAX(packetid)/10)+1)*10,0) FROM packets;",
			       -1,&compiled_stmt,NULL)!=SQLITE_OK)
	{
	    logger.message(logger.ERROR,"Error creating SQL statement in %s, to create new packetid: %s",
			   _db_name.c_str(), sqlite3_errmsg(_dbhandle));
	    return false;
	}

	for (i=0;i<5;i++)
	{
		err_code = sqlite3_step(compiled_stmt);
		if (err_code == SQLITE_BUSY)
		{
			logger.message(logger.ERROR,"Could not store packet (attempt %i of 5): database is locked by another process",i+1);
		}
		else if (err_code == SQLITE_ROW)
		{
			packetid = sqlite3_column_int(compiled_stmt,0);
			logger.message(logger.DEBUG,"Created packet storage entry, with packetid=%08x",packetid);
			break;
		} 
		else if (err_code == SQLITE_DONE)
		{
			logger.message(logger.ERROR,"Error executing SQL statement in %s to create new packetid: empty result");
			break;
		}
		else
		{
	    		logger.message(logger.ERROR,"Error executing SQL statement in %s to create new packetid: %s",
			   		_db_name.c_str(),sqlite3_errmsg(_dbhandle));
			break;
		}
	}
	sqlite3_finalize(compiled_stmt);
	if (packetid<0)
	    return false;
    }
    packet->id_set(packetid);

    timestamp	= packet->timestamp_get();
    src_ip 	= packet->source_get_ip();
    src_port 	= packet->source_get_port();
    dst_ip 	= packet->destination_get_ip();
    dst_port 	= packet->destination_get_port();
    hostname	= packet->hostname_get();

    stmt = sqlite3_mprintf("INSERT INTO packets VALUES (%u, %u, %u, %Q, %u, %Q, %u, %Q, ?);",
			   packet->id_get(),
			   timestamp.ts_sec,timestamp.ts_usec,
			   src_ip,src_port,
			   dst_ip,dst_port,
			   hostname);

    if (sqlite3_prepare_v2(_dbhandle,stmt,-1,&compiled_stmt,NULL)!=SQLITE_OK)
    {
	logger.message(logger.ERROR,"Error creating SQL statement in %s, for packet %08x: %s",
		       _db_name.c_str(),packet->id_get(),
		       sqlite3_errmsg(_dbhandle));
	sqlite3_free(stmt);
	return false;
    }
    sqlite3_free(stmt);

    data = BufferOutMemory::create();
    packet->packet_write_out((BufferOut*)data);
   
    if (sqlite3_bind_blob(compiled_stmt,1,data->get_data(),data->get_size(),SQLITE_TRANSIENT)!=SQLITE_OK)
    {
	logger.message(logger.ERROR,"Error adding body packet data in SQL statement in %s, for packet %08x",
		       _db_name.c_str(),packet->id_get());
	sqlite3_finalize(compiled_stmt);
	delete data;
	return false;
    }

    for (i=0;i<5;i++)
    {
	    err_code = sqlite3_step(compiled_stmt);
	    if (err_code == SQLITE_OK || err_code == SQLITE_DONE) 
	    {
		    logger.message(logger.DEBUG,"Saved packet %08x in %s",
				    packet->id_get(),
				    _db_name.c_str());
		    break;
	    }
	    else if (err_code == SQLITE_BUSY)
	    {
		    if (i<4)
		    {
			    logger.message(logger.WARNING,"Could not store packet (attempt %i of 5): database is locked by another process",i+1);
		    }
		    else
		    {
			    logger.message(logger.ERROR,"Could not store packet %08x in %s after 5 attempts, aborting: %s\n",
					    packet->id_get(),
					    _db_name.c_str(),
					    sqlite3_errmsg(_dbhandle));
			    sqlite3_finalize(compiled_stmt);
			    delete data;
			    return false;
		    }
	    }
	    else
	    {
		    logger.message(logger.ERROR,"Error storing packet %08x in %s: %s",
				    packet->id_get(),
				    _db_name.c_str(),
				    sqlite3_errmsg(_dbhandle));
		    sqlite3_finalize(compiled_stmt);
		    delete data;
		    return false;
	    }
    }
    sqlite3_finalize(compiled_stmt);
    delete data;
    return true;
}

void HttpPacketDB::close()
{
  if (_dbhandle)
      sqlite3_close(_dbhandle);
  _dbhandle = NULL;
}
														
std::string HttpPacketDB::_db_name = "packets.db";


