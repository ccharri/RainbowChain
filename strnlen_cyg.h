#ifndef __STRNLEN_CYG_H
#define __STRNLEN_CYG_H

unsigned strnlen(const char* str, const unsigned int max)
{
	unsigned i = 0;
	for(i = 0; i < max && str[i]; ++i)
	{}
	return i;
}

#endif