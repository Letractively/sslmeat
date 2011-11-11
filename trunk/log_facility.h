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
		log_facility() : _log(stderr), _show(true) { }
		log_facility& message(const char *format, ...); 
		void hide() 			{ _show = false; }
		void show()			{ _show = true; }
		~log_facility() { fclose(_log); }
	private:
		FILE *_log;
		bool _show;
};

extern log_facility logger;
#endif
