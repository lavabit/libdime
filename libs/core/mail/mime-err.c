void func(unsigned len);
void func(unsigned len) {

	int state = 0;

	for (unsigned i = 0; i < len && state != 3; i++) {

		if (state == 0) {
			state = 1;
		} else if (state == 1 ) {
			state = 3;
		} else if (state != 0) {
			state = 0;
		}
	}
}
