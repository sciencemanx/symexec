
#include "symexc.h"

int main() {
	int x, y, z;

	x = 3;
	y = 5;
	z = x + y;

	x = get_int();

	return z + x;
}