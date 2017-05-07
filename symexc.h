
#ifndef _SYMEXC_H_
#define _SYMEXC_H_

#include <stdio.h>
#include <stdlib.h>

int get_int();
char get_char();
void error();

int get_int() {
	int i;

	if (scanf("%d", &i) != 1) exit(-2);

	return i;
}

char get_char() {
	char c;

	if (scanf("%c", &c) != 1) exit(-2);
	
	return c;
}

void error() {
	printf("error occurred\n");
	exit(-1);
}

#endif
