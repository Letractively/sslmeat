#include "log_facility.h"
#include <ctime>

/* LOG_ID = "TTTTTTTTPPPP-VVVV" */
char LOG_ID[16];
int short LOG_ID_PID = 0;
unsigned  LOG_ID_INI = 0;

const char *logid_get()
{
  if (getpid()!=LOG_ID_PID)
  {
    LOG_ID_INI = (unsigned)time(NULL);
    LOG_ID_PID = getpid();
    sprintf(LOG_ID,"%08x-%04x",
		  LOG_ID_INI,
		  LOG_ID_PID);
  }
  return LOG_ID;
}

log_facility logger;

log_facility& log_facility::message(unsigned level, const char *format, ...)
{ 
    int slen;
    int tlen;
    char *str = NULL;
    const char *logid;
    va_list va;

    if (_level<=level)
    {
	logid = logid_get();

	slen = snprintf(str,0,"%s ",logid);
	va_start(va,format);
	tlen = vsnprintf(str,0,format,va);
	va_end(va);

	str = new char[slen+tlen+2];

	snprintf(str,slen+1,"%s ",logid);
	va_start(va,format);
	vsnprintf(str+slen,tlen+1,format,va);
	va_end(va);

	if (str[slen+tlen-1]!='\n')
	{
	    str[slen+tlen]='\n';
	    tlen++;
	}
	write(STDERR_FILENO,str,slen+tlen);

	delete [] str;
    }
    return *this;
}

