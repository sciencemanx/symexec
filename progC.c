
#include "symexc.h"

void main() {
	int a, x, i;
	int ns[5];

	for (i = 0; i < 5; i++) {
		ns[i] = get_int();
	}

	for (i = 0; i < 5; i++) {
		if (ns[i] < 0 || ns[i] > 30) return;
		if (ns[i] < i * i) return;
	}

	a = 0;
	for (i = 0; i < 5; i++) {
		a += ns[i] * 2;
	}

	if (a < 100 && a > 50) error();
}

void funcB() {
	int a, x, i;

	a = 0;

	for (i = 0; i < 5; i++) {
		x = get_int();
		if (x < 0 || x > 30) return;
		a += x;
	}

	if (a < 100 && a > 50) error();
}





