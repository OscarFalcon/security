#include "stdio.h"

#include "utils.h"



void str_rpc(char *string,char old, char new)
{
	while( *string++ != '\0')
	{
		if(*string == old)
			*string = new;
	}
	return;
}

void rmnl(char *s)
{
	str_rpc(s,'\n','\0');
	return;
}


void rmslash(char *s)
{
	str_rpc(s,'/','\0');
	return;
}


char *fgetsn(char *s, int size, FILE *stream)
{
	if(fgets(s,size,stream) == NULL)
	{
		perror("Unable to read from file..\n");
		return NULL;
	}
	str_rpc(s,'\n','\0');
	return s;
}


