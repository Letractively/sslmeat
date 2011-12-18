#ifndef LOG_FACILITY_H
#define LOG_FACILITY_H
#include <cstdio>
#include <cstdarg>
#include <time.h>
#include <sys/types.h> 
#include <unistd.h>


const char *logid_get();
const char *logid_inc();

class log_facility {
	public:
		enum {
			ALL,
			DEBUG,
			WARNING,
			ERROR,
			NONE
		};
		log_facility() : _log(stderr), _level(0) { }
		log_facility& message(unsigned level, const char *format, ...); 
		void set_verbosity(unsigned level)  { _level = level; }
		~log_facility() { fclose(_log); }
	private:
		FILE *_log;
		unsigned _level;
};

extern log_facility logger;
#endif
