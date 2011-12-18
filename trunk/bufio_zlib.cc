#include "bufio_zlib.h"
#include "log_facility.h"

BufferInflateMemory* BufferInflateMemory::create()
{
    BufferInflateMemory* obj = new BufferInflateMemory;
    int ret;
    
    ret = inflateInit2(&(obj->_strm),15 | 32);
    
    if (ret != Z_OK)
	return NULL;

    return obj;
}

bool BufferInflateMemory::write_uchar(const unsigned char c)
{
    if (_in_pos>=CHUNK)
    {
	if (zlib_inflate()!=Z_OK)
	    return false;
    }
    _in_buf[_in_pos++] = c;
    return true;
}

const unsigned char *BufferInflateMemory::get_data()
{
    if (zlib_inflate()==Z_OK)
    	return BufferOutMemory::get_data();
    return NULL;
}

unsigned BufferInflateMemory::get_size()
{
    if (zlib_inflate()==Z_OK)
	return BufferOutMemory::get_size();
    return 0;
}

BufferInflateMemory::~BufferInflateMemory()
{
    inflateEnd(&_strm); 	
}

BufferInflateMemory::BufferInflateMemory() : BufferOutMemory(CHUNK), _header_done(false)
{
    /* allocate inflate state */
    _strm.zalloc = Z_NULL;
    _strm.zfree = Z_NULL;
    _strm.opaque = Z_NULL;
    _strm.avail_in = 0;
    _strm.next_in = Z_NULL;
    _in_pos=0;
}

#define FHCRC 		2
#define FEXTRA 		4
#define FNAME		8
#define FCOMMENT 	16

int BufferInflateMemory::zlib_inflate()
{
    int ret;

    if (_in_pos==0)
	return Z_OK;

    _strm.avail_in = _in_pos;
    _strm.next_in  = _in_buf; 

    do {

	BufferOutMemory::buffer_grow(BufferOutMemory::get_size()+CHUNK);

	_strm.avail_out = CHUNK;
	_strm.next_out = BufferOutMemory::buffer_get_top();

	ret = inflate(&_strm, Z_NO_FLUSH);
	
	switch (ret) {
	    case Z_NEED_DICT:
		logger.message(logger.ERROR,"Failed zlib: Z_NEED_DICT");
		return ret;
	    case Z_DATA_ERROR:
		logger.message(logger.ERROR,"Failed zlib: Z_DATA_ERROR, %s\n",_strm.msg);
		return ret;
	    case Z_MEM_ERROR:
		logger.message(logger.ERROR,"Failed zlib: Z_MEM_ERROR\n");
		return ret;
	    case Z_STREAM_ERROR:
		logger.message(logger.ERROR,"Failed zlib: Z_STREAM_ERROR\n");
		return ret;
	}
	
	BufferOutMemory::buffer_inc_top(CHUNK-_strm.avail_out);

    } while (_strm.avail_out==0);
    
    _in_pos = 0;
    
    return Z_OK;
}


