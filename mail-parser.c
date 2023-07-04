#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

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
	errno = 0;
	int fd = open(argv[1], O_RDONLY, S_IRUSR);
	if (fd == -1) {
		perror("open() error: ");
		exit(3);
	}

	// Get file size
	struct stat sb;
	errno = 0;
	if (fstat(fd, &sb) == -1) {
		perror("fstat() error: ");
	}
	printf("File size: %ld B\n", sb.st_size);

	// Map file in memory
	char *file_in_memory = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_in_memory == MAP_FAILED) {
		perror("mmap() error: ");
	}

	// Separate above output from below output
	printf("\n");

	// TODO: Do some work on file

	// Print the file
	for (int i=0; i < sb.st_size; i++) {
		printf("%c", file_in_memory[i]);
	}
	printf("\n");

	// Unmap the file from memory
	errno = 0;
	if (munmap(file_in_memory, sb.st_size) == -1) {
		perror("munmap() error: ");
	}

	// Try to close the file
	errno = 0;
	if (close(fd) == -1) {
		perror("close() error: ");
		exit(3);
	}
}
