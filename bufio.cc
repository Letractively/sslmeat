#include "bufio.h"
#include <cstring>

/*******************/
/* BufferIn class */
/*******************/

bool BufferIn::read_block(unsigned &len, unsigned char *dest)
{
    unsigned p=0;
    unsigned char c;

    for (p=0;p<len;p++) 
    {
	if (!read_uchar(c)) break;
	dest[p]=(unsigned char)c;
    }

    if (p!=len)
    {
	len=p;
	return false;
    }

    return true;
}

bool BufferIn::read_uchar(unsigned char &c)
{
    if (read_end())
	return false;
    c = 0;
    return true;
}

bool BufferIn::read_char(char &c)
{
    return read_uchar((unsigned char &)c);
}

bool BufferIn::read_line(std::string &s)
{
    unsigned char c;
    s="";

    while (read_uchar(c))
    {
	s += c;
	if (c=='\n') return true;
    }
    return (s.size()!=0);
}

bool BufferIn::read_end() const
{
    return false;
}

/********************/
/* BufferOut class */
/********************/

bool BufferOut::write_block(unsigned &len, const unsigned char *src)
{
    unsigned p=0;

    for (p=0;p<len;p++) {
	if (!write_uchar(src[p])) break;
    }

    if (p!=len)
    {
	len=p;
	return false;
    }
    return true;
}

bool BufferOut::write_uchar(const unsigned char c)
{
    if (write_end())
	return false;
    return true;
}

bool BufferOut::write_char(const char c)
{
    return write_uchar((const unsigned char)c);
}

bool BufferOut::write_line(const std::string &s)
{
    unsigned len = s.size();
    return write_block(len,(const unsigned char *)s.data());
}

bool BufferOut::write_end() const
{
    return false;
}

/************************/
/* BufferInMemory class */
/************************/

BufferInMemory* BufferInMemory::create(unsigned src_len, const unsigned char *src)
{
    return new BufferInMemory(src_len,src);
}

bool BufferInMemory::read_uchar(unsigned char &c)
{
    if (read_end())
   	return false;
    c = _buf_in_data[_buf_in_pos++];
    return true;
}


BufferInMemory::~BufferInMemory()
{
    free(_buf_in_data);
}

BufferInMemory::BufferInMemory(unsigned src_len, const unsigned char *src)
{
    _buf_in_len = src_len;
    _buf_in_pos = 0;
    _buf_in_data = (unsigned char *)malloc(_buf_in_len);
    memcpy(_buf_in_data,src,_buf_in_len);
}


/***************************/
/* BufferOutMemory class   */
/***************************/

unsigned char *BufferOutMemory::buffer_get_top()
{
	return _buf_out_data+_buf_out_len;
}

void BufferOutMemory::buffer_inc_top(unsigned incr)
{
	_buf_out_len += incr;
}

bool BufferOutMemory::buffer_grow(unsigned new_size)
{
	if (new_size<=_buf_out_max)
	    return true;
	while (_buf_out_max<new_size)
	    _buf_out_max<<=1;
	_buf_out_data = (unsigned char *)realloc(_buf_out_data, _buf_out_max);
	return _buf_out_data!=NULL;
}    

BufferOutMemory* BufferOutMemory::create(unsigned pre_alloc)
{
    return new BufferOutMemory(pre_alloc);
}

bool BufferOutMemory::write_uchar(const unsigned char c)
{
    buffer_grow(_buf_out_len+1);
    _buf_out_data[_buf_out_len++]=c;
    return true;
}

BufferOutMemory::~BufferOutMemory()
{
    free(_buf_out_data);
}

BufferOutMemory::BufferOutMemory(unsigned pre_alloc)
{
    _buf_out_len = 0;
    _buf_out_max = pre_alloc;
    _buf_out_data = (unsigned char *)malloc(_buf_out_max);
}

/*************************/
/* BufferInOutFile class */
/*************************/

BufferInOutFile::BufferInOutFile(int filedes) : _filedes(filedes), _read_pos(0), _read_size(0), _write_size(0), _eof(false)
{ 
	/* empty */ 
}


BufferInOutFile* BufferInOutFile::create(int filedes)
{
	return new BufferInOutFile(filedes);
}

bool BufferInOutFile::read_load()
{
    if (_eof) return false;
    _read_pos = 0;
    if ((_read_size = read(_filedes,_read_buf,BUFIO_BUFLEN))==0)
    {
	_eof = true;
	return false;
    }
    return true;
}

bool BufferInOutFile::read_uchar(unsigned char &c)
{
	if (_read_pos==_read_size) read_load();
	if (_eof) return false;
	c = _read_buf[_read_pos++];
	return true;
}

bool BufferInOutFile::write_flush()
{
    if (_eof) return false;
    if (_write_size==0) return true; 

    if ((unsigned)write(_filedes,_write_buf,_write_size)!=_write_size)
    {
	_eof = true;
	return false;
    }

    _write_size=0;
    return true;
}

bool BufferInOutFile::write_uchar(const unsigned char c)
{
	if (_write_size==BUFIO_BUFLEN) write_flush(); 
	if (_eof) return false; 
	_write_buf[_write_size++]=c;
	return true;
}

BufferInOutFile::~BufferInOutFile()
{
	write_flush();
}

/*******************************/
/* VERY BASIC UNIT TESTING :-) */
/*******************************/
#ifdef TEST_BUFIO_CC
int main(int argc, char **argv)
{
	BufferInOutFile *out = BufferInOutFile::create(1);
	BufferInOutFile *in  = BufferInOutFile::create(0);
	std::string line;

       do {
	    fprintf(stderr,"Your input: ");
	    if (in->read_line(line)==false) break;
	    fprintf(stderr,"You typed: ");
	    if (out->write_line(line)==false) break;
	    out->write_flush();
	    fprintf(stderr,"OK.\n");
	} while (line!="\n");
	
	delete out;
	delete in;
}
#endif
