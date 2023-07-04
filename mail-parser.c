#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/*
The following exit values are defined:

0: normal exit
1: generic error
2: command-line argument(s) provided are not valid
3: I/O error

*/

int main(int argc, char* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <path/to/email/message>\n", argv[0]);
		exit(2);
	}

	// Try to open the file
	FILE *fp;
	errno = 0;
	fp = fopen(argv[1], "r");
	if (fp == 0 && errno != 0) {
		perror("I/O error");
		exit(3);
	}

	// TODO: Do some work with file

	// Try to close the file
	errno = 0;
	if (fclose(fp) != 0) {
		perror("I/O error");
		exit(3);
	}
}
