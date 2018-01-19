#include <stdio.h>
#include <stdarg.h>

int verbose_flag;

int printfv(const char* format, ...) {
	if (!verbose_flag) {
		return 0;
	}

	int ret;
	va_list args;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
}


