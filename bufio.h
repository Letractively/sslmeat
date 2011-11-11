#ifndef BUFIO_H
#define BUFIO_H

#include <string>
#include <cstdlib>

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
	TypeName(const TypeName&); \
	void operator=(const TypeName&)	


class BufferIn {
	public:
		virtual bool read_block(unsigned &len, unsigned char *dest);
		virtual bool read_uchar(unsigned char &c);
		virtual bool read_char(char &c);
		virtual bool read_line(std::string &s);
		virtual bool read_end() const;

		virtual ~BufferIn() {}

	protected:
		BufferIn() {}

	private:
		DISALLOW_COPY_AND_ASSIGN(BufferIn);
};

class BufferOut {
	public:
		virtual bool write_block(unsigned &len, const unsigned char *src);
		virtual bool write_uchar(const unsigned char c);
		virtual bool write_char(const char c);
		virtual bool write_line(const std::string &s);
		virtual bool write_end() const;

		virtual ~BufferOut() {}
	
	protected:
		BufferOut() {}

	private:
		DISALLOW_COPY_AND_ASSIGN(BufferOut);
};

class BufferInMemory : public BufferIn {
	public: 
		static BufferInMemory* create(unsigned src_len, const unsigned char *src);

		virtual bool read_uchar(unsigned char &c);
		virtual const unsigned char *get_data() 	{ return _buf_in_data+_buf_in_pos; }
		virtual unsigned get_size() 			{ return _buf_in_len-_buf_in_pos; }
		virtual bool read_end() 			{ return _buf_in_len==_buf_in_pos; }

		virtual ~BufferInMemory();	

	protected:
		BufferInMemory(unsigned src_len = 0, const unsigned char *src = NULL);
	
	private:
		unsigned char *_buf_in_data;
		unsigned _buf_in_len;
		unsigned _buf_in_pos;

		DISALLOW_COPY_AND_ASSIGN(BufferInMemory);
};

class BufferOutMemory : public BufferOut {
	public: 
		static BufferOutMemory* create(unsigned pre_alloc = 1024);

		virtual bool write_uchar(const unsigned char c);
		virtual const unsigned char *get_data()  	{ return _buf_out_data; }
		virtual unsigned get_size() 			{ return _buf_out_len; }

		virtual ~BufferOutMemory();
	
	protected:
		BufferOutMemory(unsigned pre_alloc = 1024);
		unsigned char *buffer_get_top();
		void buffer_inc_top(unsigned increment);
		bool buffer_grow(unsigned new_size);

	private:
		unsigned char *_buf_out_data;
		unsigned _buf_out_len;
		unsigned _buf_out_max;

		DISALLOW_COPY_AND_ASSIGN(BufferOutMemory);
};


#define BUFIO_BUFLEN 8192

class BufferInOutFile : public BufferIn, public BufferOut {
	public:
		static BufferInOutFile* create(int filedes);

		virtual bool read_uchar(unsigned char &c);
		virtual bool read_end() const			{ return _eof; }
		virtual bool read_load();
		virtual bool write_uchar(const unsigned char c);
		virtual bool write_end() const			{ return _eof; }
		virtual bool write_flush();
		int get_fd() const 				{ return _filedes; }

		virtual ~BufferInOutFile();

	protected:
		BufferInOutFile(int filedes = -1);

		int _filedes;

		unsigned char _read_buf[BUFIO_BUFLEN];
		unsigned _read_pos;
		unsigned _read_size;

		unsigned char _write_buf[BUFIO_BUFLEN];
		unsigned _write_size;
		bool _eof;

	private:
		DISALLOW_COPY_AND_ASSIGN(BufferInOutFile);
};

#endif
