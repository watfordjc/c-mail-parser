#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

int valid_header_character(unsigned char c)
{
	return c > 32 && c < 127 && c != 58;
}

int valid_header_wsp(unsigned char c)
{
	return c == ' ' || c == '\t';
}

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
	unsigned char *file_in_memory = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_in_memory == MAP_FAILED) {
		perror("mmap() error: ");
	}

	// Separate above output from below output
	printf("\n");

	int in_header_name = 0;
	int in_header_value = 0;
	int line_ending_lf = 0;
	int line_ending_crlf = 0;
	int line_ending_length = 0;
	int on_newline = 1;
	int message_body_found = 0;

	unsigned int line_endings[4096] = { 0 };
	int current_line_ending = 0;
	unsigned int header_name_lengths[4096] = { 0 };
	unsigned int header_count = 0;
	int body_start = -1;

	// Check the first character is permitted in header field names
	if (!valid_header_character(file_in_memory[0])) {
		// If the first character is invalid, this might not be an e-mail
		fprintf(stderr, "Error: Invalid character in header field name at byte 0.\n");
	} else {
		// The first character is valid, assume we are in the first header
		for (int i = 0; i < sb.st_size; i++)
		{
			// If we are on a new line, determine the type of line we are on
			if (on_newline == 1) {
				if (valid_header_character(file_in_memory[i])) {
					// This line is a new header line and we're in a new header field-name
					header_count++;
					in_header_name = 1;
				} else if (line_ending_crlf == 1 && file_in_memory[i] == '\r' && file_in_memory[i + 1] == '\n') {
					// This line only contains CRLF - message body starts on next line
					body_start = i + 2;
				} else if (line_ending_lf == 1 && file_in_memory[i] == '\n') {
					// This line only contains LF - message body starts on next line
					body_start = i + 1;
				} else if (valid_header_wsp(file_in_memory[i])) {
					// This line is a continuation line - the previous LF character was to fold the "current" line
					current_line_ending--;
					// TODO: Can header field-names be folded?
					in_header_name = 0;
				} else {
					// This line starts with a character that RFC 5322 does not permit in header field-names
					// Print an error
					fprintf(stderr, "Unexpected character at byte %d\n", i);
				}
				// Unset the flag enabling the for loop's 'first character on line' checks
				on_newline = 0;
			}
			// If the start of the message body has been detected, print some information and exit the for loop
			if (body_start > 0) {
				printf("Number of headers detected: %d\n", header_count);
				printf("Message body starts at byte %d\n", body_start);
				break;
			}
			if (in_header_name) {
				// TODO: Sanity check that header field-name meets minimum length (1?) requirements - store i before while and compare i after
				// If we're inside a header field-name, read bytes until we reach a character not valid in header field-names
				while (valid_header_character(file_in_memory[i]))
				{
					i++;
					continue;
				}
				// If the first character on a line not valid in header field-names is a colon, calculate the length of the header's field-name
				if (file_in_memory[i] == ':') {
					in_header_name = 0;
					header_name_lengths[current_line_ending] = current_line_ending == 0 ? i : i - line_endings[current_line_ending - 1] - line_ending_length;
					continue;
				}
				// TODO: Warn on non-compliant characters
			} else {
				// If we're not inside a header field name, detect the next line ending
				if (file_in_memory[i] == '\r') {
					if (!file_in_memory[i + 1] == '\n') {
						fprintf(stderr, "CR character at byte %d is not followed by LF\n", i);
					} else {
						// If this is the first CRLF detected, note CRLF line endings are used
						if (line_ending_crlf == 0) {
							line_ending_crlf = 1;
							line_ending_length = 2;
							printf("Line endings are CRLF\n");
						}
					}
				} else if (file_in_memory[i] == '\n') {
					// If CRLF line endings aren't used and this is the first LF detected, note LF line endings are used
					if (line_ending_crlf == 0 && line_ending_lf == 0) {
						line_ending_lf = 1;
						line_ending_length = 1;
						printf("Line endings are LF\n");
					}
					// Store the byte position of the last character (LF) on the line
					line_endings[current_line_ending] = i;
					// Increase the line ending count for the next iteration of the for loop
					current_line_ending++;
					// Set the flag enabling the for loop's 'first character on line' checks
					on_newline = 1;
				}
				// TODO: Do headers require a field-body?
				// TODO: Warn on invalid characters in header field-bodies
			}
		}
	}

	printf("\n");

	printf("Header names...\n");
	// TODO: Can header field-names be folded?
	// TODO: Check maximum length of field-name, for now assuming (strlen(field-name + colon) <= 997) characters
	const unsigned int MAX_HEADER_FIELD_NAME_LENGTH = 997;
	// Allocate some memory for storing a header field-name
	char* current_header_name = calloc(sizeof(char), MAX_HEADER_FIELD_NAME_LENGTH);
	// Create an array to store the header indexes of content-type headers
	unsigned int content_headers[4096] = { 0 };
	// Create a variable for storing the number of content-type headers
	unsigned int content_header_count = 0;
	// Iterate through the headers
	for (int i = 0; i < header_count; i++)
	{
		// The header starts either at byte 0, or at the first byte after the previous header's line ending
		int file_offset = i == 0 ? 0 : line_endings[i - 1] + line_ending_length;
		// Iterate through the header's field-name and copy the characters
		for (int j = 0; j < header_name_lengths[i]; j++)
		{
			current_header_name[j] = file_in_memory[file_offset + j];
		}
		if (strncasecmp("content-type", current_header_name, header_name_lengths[i]) == 0) {
			// If the header has a field-name of content-type, store its header index number and increase the count
			content_headers[content_header_count] = i;
			content_header_count++;
		}
		// Print the header field-name
		printf("%s\n", current_header_name);
		// Zero the memory for storing a header field-name
		bzero(current_header_name, MAX_HEADER_FIELD_NAME_LENGTH);
	}
	// Free the memory for storing a header field-name
	free(current_header_name);
	printf("\n");

	// Sanity check the number of content-type headers, and warn if there is a potential issue
	// TODO: Do the RFCs say how differing headers with the same field-name should be treated?
	if (content_header_count == 0 && body_start > 0) {
		printf("No Content-Type header, treat message body as text/plain and US-ASCII\n");
	} else if (body_start == 0 && content_header_count > 0) {
		printf("Content-header present, but no message body detected.\n");
	} else if (content_header_count > 1) {
		printf("More than one Content-Header detected.\n");
	} else if (body_start > 0 && content_header_count == 1) {
		printf("Content-Type header says body is of type: ");
	}

	// Allocate some memory for storing the field-body of the first content-type header
	char* current_header_value = calloc(sizeof(char), 4096);
	// Calculate the byte offset for the field-body
	// TODO: Do the RFCs say a field-name should be followed by : and SP? strlen(": ") is the '+ 2' at end of offset calculation
	int file_offset = content_headers[0] == 0 ? 0 : line_endings[content_headers[0] - 1] + line_ending_length + header_name_lengths[content_headers[0]] + 2;
	// Create a variable for storing the entire length (including CR/LF/SP/HTAB folding) of the header line
	int line_length = 0;
	// Calculate the line length
	if (body_start > 0 && content_headers[0] > 0) {
		// If it isn't the first header and a body has been detected, use the end of this line and the end of the previous line to calculate line length
		line_length = line_endings[content_headers[0]] - line_endings[content_headers[0] - 1] - line_ending_length;
	} else if (content_headers[0] == 0 && header_count > 1) {
		// If it is the first header and there is more than one header, use the end of this line as the line length
		line_length = line_endings[content_headers[0]];
	} // TODO: Handle the non-complicant case of it being the last header and no message body being detected, and warn about it

	char c;
	// Iterate through the field-body and copy the characters to memory
	for (int i = 0, j = 0; i < line_length - header_name_lengths[content_headers[0]] - 2; i++)
	{
		c = file_in_memory[file_offset + i];
		if (c == '\r' || c == '\n') {
			j++;
			continue;
		}
		current_header_value[i - j] = c;
	}
	// TODO: Create functions for parsing different field-body types
	// TODO: Improve parsing of a content-type header field-body
	if (strlen(current_header_value) > 0) {
		// Print the field-body
		printf("%s\n", current_header_value);
		// Find the first semi-colon in the content-type header's field-body
		// TODO: A missing semi-colon is not handled correctly
		char* first_semicolon = strstr(current_header_value, ";");
		int first_semicolon_index = first_semicolon - current_header_value;
		if (strncmp("text/plain", current_header_value, first_semicolon_index) == 0) {
			// If content-type is text/plain, print to stdout
			// TODO: Handle different character sets
			printf("text/plain detected, printing message body to stdout...\n\n");
			for (int i = body_start; i < sb.st_size; i++)
			{
				c = file_in_memory[i];
				printf("%c", file_in_memory[i]);
			}
			printf("\n");
		}
	}

	// Free the memory for storing the field-body of the first content-type header
	free(current_header_value);

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
