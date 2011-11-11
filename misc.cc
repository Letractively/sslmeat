#include "misc.h"

size_t strlcpy(char *dst, const char *src, size_t n)
{
    strncpy(dst,src,n-1);
    dst[n-1]=0;
    return strlen(src);
}
