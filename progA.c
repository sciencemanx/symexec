
#include "symexc.h"

void main() {
	int a, b;

	a = get_int();
	b = get_int();


	if (a < 0 || b < 0) return;
	if (b > 10) return;

	if (a % 2 == 0) return;

	if (a + b == 10) {
		if (a < b) error();
	}
}
