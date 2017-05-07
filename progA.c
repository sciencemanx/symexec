
#include "symexc.h"

void main() {
	int a, b;

	a = get_int();
	b = get_int();

	if (b > 10 || b == 0) return;
	// if (a % 2 == 0) return;
	if (a + b == 10) {
		if (a < b) error();
	}
}
