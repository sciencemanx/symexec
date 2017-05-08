
#include "symexc.h"

void main() {
	int x, i, a;

	a = 0;
	for (i = 0; i < 7; i++) {
		x = get_int();
		if (x < i * i) return;
		if (x >= (i + 1) * (i + 1)) return;
		a += x;
	}


	if (a == 100) error();
}




