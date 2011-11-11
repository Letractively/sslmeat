#ifndef BUFIO_ZLIB_H
#define BUFIO_ZLIB_H

#include "bufio.h"
#include <zlib.h>

#define CHUNK 16384

class BufferInflateMemory: public BufferOutMemory { 
	public:
		static BufferInflateMemory* create();
		virtual bool write_uchar(const unsigned char c);
		const unsigned char *get_data();
                unsigned get_size();
		virtual ~BufferInflateMemory();
	protected:
		BufferInflateMemory();
	private:
		z_stream _strm;
		unsigned char _in_buf[CHUNK];
		unsigned _in_pos;
		
		int zlib_inflate();
		bool _header_done;
		DISALLOW_COPY_AND_ASSIGN(BufferInflateMemory);		
};

#endif
