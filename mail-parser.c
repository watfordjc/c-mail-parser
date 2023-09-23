#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <locale.h>
#include <openssl/evp.h>

// gcc mail-parser.c -o mail-parser -lssl -lcrypto

/* Maximum supported line ending length: \r\n = 2, \n = 1, etc. */
#define MAX_LINE_ENDING_LENGTH 2
/* Maximum line length - TODO: includes/excludes line ending? */
#define MAX_LINE_LENGTH 1000
/* Maximum supported line ending count before message body starts */
#define MAX_MULTILINE_HEADER_LINES 4096
/* Maximum supported multiline header count before message body starts */
#define MAX_MULTILINE_HEADER_COUNT 4096
/* Maximum supported number of identical header names */
#define MAX_IDENTICAL_HEADER_COUNT 128
/* Maximum supported header name length (includes trailing colon) */
#define MAX_HEADER_NAME_LENGTH 1000
/* Maximum supported multiline header body field length (i.e. maximum length of a header value) */
#define MAX_HEADER_BODY_LENGTH 4095

int valid_header_character(unsigned char c)
{
	return c > 32 && c < 127 && c != 58;
}

int valid_header_wsp(unsigned char c)
{
	return c == ' ' || c == '\t';
}

int get_header_name_length(unsigned char* header, size_t len)
{
	for (int i = 0; i < len; i++)
	{
		if (valid_header_character(header[i]))
		{
			continue;
		}
		return i;
	}
}

unsigned char* base64_decode(const char *encoded_bytes, int length, int* output_length) {
	//printf("Next 80 characters: %.*s\n", 80, &encoded_bytes[0]);
	const int predicted_length = 3 * length / 4;
//	printf("Predicted length: %d bytes\n", predicted_length);

	unsigned char* decoded_bytes = calloc(predicted_length + 1, 1);
	*output_length = EVP_DecodeBlock(decoded_bytes, encoded_bytes, length);
//	printf("Output length: %d bytes\n", *output_length);
	if (predicted_length != *output_length) {
		fprintf(stderr, "Length mismatch: predicted %d bytes but output is %d bytes\n", predicted_length, output_length);
	}

	return decoded_bytes;
}

unsigned char* sha1_hash(const char *data, int length) {
	unsigned char digest_binary[21] = { 0 };// = calloc(20 + 1, sizeof(char));
	unsigned char* digest_hex = calloc(40 + 1, sizeof(char));
	unsigned char digest_hex_temp[3] = { 0 };// = calloc(3, sizeof(char));

	EVP_Digest(data, length, digest_binary, NULL, EVP_sha1(), NULL);
	for (int i = 0; i < 20; i++) {
		snprintf(digest_hex_temp, 3, "%02x", digest_binary[i]);
		memcpy(&digest_hex[i*2], digest_hex_temp, 2);
	}
//     free(digest_binary);
	return digest_hex;
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

	/* Try to open the file */
	errno = 0;
	int fd = open(argv[1], O_RDONLY, S_IRUSR);
	if (fd == -1) {
		perror("open() error: ");
		exit(3);
	}

	/* Get file size */
	struct stat sb;
	errno = 0;
	if (fstat(fd, &sb) == -1) {
		perror("fstat() error: ");
		exit(3);
	}
	printf("Info: File size is %ld bytes\n", sb.st_size);

	/* Map file in memory */
	unsigned char *file_in_memory = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_in_memory == MAP_FAILED) {
		perror("mmap() error: ");
	}

	/* Separate above output from below output */
	printf("\n");

	/* TODO: Parsing needs to be recursive so that e-mails within e-mails are parsed properly */

	char line_ending[MAX_LINE_ENDING_LENGTH + 1];
	int line_ending_length = 0;
	int message_body_found = 0;

	unsigned int line_start_offsets[4096] = { 0 };
	int current_line_ending = 0;
	unsigned int header_name_lengths[4096] = { 0 };
	unsigned int header_count = 0;
	int body_start = -1;

	/* Check the first character is permitted in header field names */
	if (!valid_header_character(file_in_memory[0])) {
		/* If the first character is invalid, this might not be an e-mail */
		fprintf(stderr, "Error: Invalid character in header field name at byte 0.\n");
		exit(1);
	}

	/* Current position in file */
	int position = 0;
	/* Find next CR character */
	unsigned char* next_cr = memmem(&file_in_memory[position], sb.st_size - position, "\r", 1);
	/* Store offset of next CR character, or -1 if none */
	int next_cr_offset = next_cr == NULL ? -1 : (int)(next_cr - &file_in_memory[0]);
	/* Find next LF character */
	unsigned char* next_lf = memmem(&file_in_memory[position], sb.st_size - position, "\n", 1);
	/* Store offset of next LF character, or -1 if none */
	int next_lf_offset = next_lf == NULL ? -1 : (int)(next_lf - &file_in_memory[0]);

	printf("Info: The next CR after byte %d is at position %d\n", position, next_cr == NULL ? -1 : next_cr_offset);
	printf("Info: The next LF after byte %d is at position %d\n", position, next_lf == NULL ? -1 : next_lf_offset);

	/* Attempt to detect line ending format */
	if (next_lf_offset == next_cr_offset + 1) {
		strcpy(line_ending, "\r\n");
		printf("Info: CRLF line endings detected\n");
	} else if (next_lf_offset == -1 && next_cr_offset > 0) {
		strcpy(line_ending, "\r");
		line_ending_length = strlen(line_ending);
		printf("Info: CR line endings detected\n");
	} else if (next_cr_offset == -1 && next_lf_offset > 0) {
		strcpy(line_ending, "\n");
		printf("Info: LF line endings detected\n");
	} else {
		fprintf(stderr, "Warning: Cannot detect any line endings\n");
		//free(line_ending);
		exit(1);
	}
	line_ending_length = strlen(line_ending);

	/* Attempt to detect first double line ending (offset where a message body might start) */
	unsigned char double_line_ending_chars[MAX_LINE_ENDING_LENGTH * 2 + 1];
	strcpy(double_line_ending_chars, line_ending);
	strcat(double_line_ending_chars, line_ending);
	unsigned char* double_line_ending = memmem(&file_in_memory[position], sb.st_size - position, double_line_ending_chars, strlen(double_line_ending_chars));
	body_start = double_line_ending == NULL ? -1 : (int)(double_line_ending - &file_in_memory[0]) + strlen(double_line_ending_chars);
	printf("Info: Message body starts at position %d\n", body_start);
	printf("\n");

	int headers_last_byte = body_start == -1 ? sb.st_size : body_start;
	unsigned char* next_line_ending = NULL;
	unsigned char* header_name_ending = NULL;
	unsigned char header_name_chars[MAX_HEADER_NAME_LENGTH + 1] = { 0 };
	printf("Info: Current position: %d\n", line_start_offsets[header_count - 1]);
	printf("Info: Indexing byte offsets of header lines...\n  ");
	for (header_count = 0, position = 0; position < headers_last_byte; position++)
	{
		//printf("Current position pointer: %p\n", &file_in_memory[position]);
		//printf("i = %d, position = %d\n", i, position);
		next_line_ending = memmem(&file_in_memory[position], headers_last_byte - position, line_ending, line_ending_length);
		//printf("next_line_ending: %p\n", &next_line_ending);
		if (valid_header_character(file_in_memory[position])) {
			line_start_offsets[header_count] = position;
			header_name_ending = memmem(&file_in_memory[position], headers_last_byte - position, ":", 1);
			//printf("header_name_ending: %p\n", &header_name_ending);
			if (next_line_ending == NULL || header_name_ending == NULL) {
				fprintf(stderr, "\nWarning: Line starting at byte %d does not contain both a colon and a line ending\n");
			}
			if (header_name_ending < next_line_ending) {
				header_name_lengths[header_count] = (int)(header_name_ending - &file_in_memory[position]) + 1;
				memcpy(header_name_chars, &file_in_memory[position], header_name_lengths[header_count]);
				//printf("header_name_lengths[%d] = %d\n", i, header_name_lengths[i]);
				//printf("  Info: Header #%d \"%s\" starting at byte offset %d\n", header_count, header_name_chars, position);
				printf("%6d ", position);
				bzero(header_name_chars, (MAX_HEADER_NAME_LENGTH + 1) * sizeof(char));
				header_count++;
				if (header_count %6 == 0) {
					printf("\n  ");
				}
			}
		}
		if (next_line_ending != NULL) {
			position = (int)(next_line_ending - &file_in_memory[0]);
		}
	}

	printf("\nInfo: Current position: %d\n", position);

	printf("\nIndexing specific headers...\n");

	bzero(header_name_chars, (MAX_HEADER_NAME_LENGTH + 1) * sizeof(char));
	int header_name_len = 0;
	int header_return_path[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_return_path_count = 0;
	int header_date[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_date_count = 0;
	int header_message_id[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_message_id_count = 0;
	int header_to[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_to_count = 0;
	int header_from[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_from_count = 0;
	int header_subject[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_subject_count = 0;
	int header_dkim_signature[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_dkim_signature_count = 0;
	int header_mime_version[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_mime_version_count = 0;
	int header_content_type[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
	int header_content_type_count = 0;
	for (int i = 0; i < header_count; i++)
	{
		header_name_len = get_header_name_length(&file_in_memory[line_start_offsets[i]], header_name_lengths[i]);
		//printf("Header name length: %d\n", header_name_len);
		memcpy(header_name_chars, &file_in_memory[line_start_offsets[i]], header_name_len);
		header_name_chars[header_name_len + 0] = ':';
		header_name_chars[header_name_len + 1] = '\0';
		//printf("%s\n", header_name_chars);

		if (strcasecmp("return-path:", header_name_chars) == 0) {
			header_return_path[header_return_path_count] = i;
			header_return_path_count++;
			printf("  'return-path' trace header at index %d\n", i);
		} else if (strcasecmp("date:", header_name_chars) == 0) {
			header_date[header_date_count] = i;
			header_date_count++;
			printf("  'date' header at index %d\n", i);
		} else if (strcasecmp("to:", header_name_chars) == 0) {
			header_to[header_to_count] = i;
			header_to_count++;
			printf("  'to' header at index %d\n", i);
		} else if (strcasecmp("from:", header_name_chars) == 0) {
			header_from[header_from_count] = i;
			header_from_count++;
			printf("  'from' header at index %d\n", i);
		} else if (strcasecmp("subject:", header_name_chars) == 0) {
			header_subject[header_subject_count] = i;
			header_subject_count++;
			printf("  'subject' header at index %d\n", i);
		} else if (strcasecmp("message-id:", header_name_chars) == 0) {
			header_message_id[header_message_id_count] = i;
			header_message_id_count++;
			printf("  'message-id' header at index %d\n", i);
		} else if (strcasecmp("dkim-signature:", header_name_chars) == 0) {
			header_dkim_signature[header_dkim_signature_count] = i;
			header_dkim_signature_count++;
			printf("  'dkim-signature' trace header at index %d\n", i);
		} else if (strcasecmp("mime-version:", header_name_chars) == 0) {
			header_mime_version[header_mime_version_count] = i;
			header_mime_version_count++;
			printf("  'mime-version' header at index %d\n", i);
		} else if (strcasecmp("content-type:", header_name_chars) == 0) {
			header_content_type[header_content_type_count] = i;
			header_content_type_count++;
			printf("  'content-type' header at index %d\n", i);
		} else {
			printf("  Unhandled header (%s) at index %d\n", header_name_chars, i);
		}
		bzero(header_name_chars, (MAX_HEADER_NAME_LENGTH + 1) * sizeof(char));
	}

	printf("\nValidating header counts...\n");
	printf("  Return-Path: header SHOULD occur 1 time for delivered messages (RFC 5321): %s\n", header_return_path_count == 1 ? "✅ pass" : "❌ fail");
	printf("  Date: header MUST occur 1 time (RFC 5322): %s\n", header_date_count == 1 ? "✅ pass" : "❌ fail");
	printf("  From: header MUST occur 1 time (RFC 5322): %s\n", header_from_count == 1 ? "✅ pass" : "❌ fail");
	printf("  Message-ID: header SHOULD occur 1 time (RFC 5322): %s\n", header_message_id_count == 1 ? "✅ pass" : "❌ fail");
	printf("  To: header should occur 0-1 times (RFC 5322): %s\n", header_to_count == 1 ? "✅ pass" : "❌ fail");
	printf("  Subject: header should occur 0-1 times (RFC 5322): %s\n", header_subject_count == 1 ? "✅ pass" : "❌ fail");
	printf("  MIME-Version: header should not occur if not a MIME message (RFC 2045): %s\n", header_mime_version_count == 0 ? "✅ pass (not a MIME message)" : "❌ fail (might be a MIME message)");
	printf("  MIME-Version: header MUST occur 1 time if a MIME message (RFC 2045): %s\n", header_mime_version_count == 1 ? "✅ pass (MIME message)" : "❌ fail (might not be a MIME message)");
	printf("  Content-Type: header should occur 0-1 times (RFC 2045): %s\n", header_content_type_count <= 1 ? "✅ pass" : "❌ fail");

	int line_start_offset = -1;
	int line_length = -1;
	int field_body_offset = -1;
	char field_body_chars[MAX_HEADER_BODY_LENGTH + 1];
	int field_body_length = -1;
	int is_mime_v1 = -1;
	if (header_mime_version_count == 1) {
		int header_index = header_mime_version[0];
		printf("\nValidating MIME-Version header (does not support comments)...\n");
		line_start_offset = line_start_offsets[header_index];
		line_length = -1;
		if (header_index + 1 < header_count) {
			/* If there are subsequent headers, use the start of the next header and the start of this header to calculate line length */
			line_length = line_start_offsets[header_index + 1] - line_start_offset - line_ending_length;
		} else if (body_start > 0) {
			/* If this is the last header and there is a message body, use the start of message body and the start of this header to calculate line length */
			line_length = body_start - line_start_offset - line_ending_length - line_ending_length;
		}
		//printf("  Line length: %d bytes\n", line_length);
		field_body_offset = line_start_offset + header_name_lengths[header_index];
		//printf("  field-body offset: %d bytes\n", field_body_offset);
		field_body_length = line_length - header_name_lengths[header_index];
		//printf("  field-body length: %d bytes\n", field_body_length);
		printf("  Parsing field-body...\n");
		for (int i = 0, pos = 0; pos < field_body_length; pos++)
		{
			unsigned char c = file_in_memory[field_body_offset + pos];
			//printf("%d = %d (%c)\n", i, c, c);
			if (c > 47 && c < 58 || c == 46) {
				memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
				i++;
			}
		}
		printf("    MIME-Version = '%s'\n", field_body_chars);
		if (strncmp("1.0", field_body_chars, 3) == 0) {
			is_mime_v1 = 1;
			printf("  MIME-Version field-body validated.\n");
		}
	}

	if (header_content_type_count == 1) {
		int header_index = header_content_type[0];
		printf("\nValidating Content-Type header (does not support comments)...\n");
		line_start_offset = line_start_offsets[header_index];
		//printf("  Line start byte offset: %d\n", line_start_offset);
		line_length = -1;
		if (header_index + 1 < header_count) {
			// If there are subsequent headers, use the start of the next header and the start of this header to calculate line length
			line_length = line_start_offsets[header_index + 1] - line_start_offset - line_ending_length;
		} else if (body_start > 0) {
			// If this is the last header and there is a message body, use the start of message body and the start of this header to calculate line  length
			line_length = body_start - line_start_offset - line_ending_length - line_ending_length;
		}
		//printf("  Line length: %d bytes\n", line_length);
		field_body_offset = line_start_offset + header_name_lengths[header_index];
		//printf("  field-body offset: %d bytes\n", field_body_offset);
		field_body_length = line_length - header_name_lengths[header_index];
		//printf("  field-body length: %d bytes\n", field_body_length);
		int inside_quote = 0;
		printf("  Parsing field-body...\n");
		for (int i = 0, pos = 0; pos < field_body_length; pos++)
		{
			unsigned char c = file_in_memory[field_body_offset + pos];
			//printf("%d = %d (%c)\n", i, c, c);
			if (c != '\r' && c != '\n' && c > 32 && c < 127) {
				memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
				if (c == '"') {
					inside_quote ^= 1;
					printf("    Inside Quoted-String: %s\n", inside_quote == 1 ? "true" : "false");
				}
				i++;
			} else if (inside_quote == 1 && (c == 32 || c == '\t')) {
				memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
				i++;
			}
		}
		printf("    Content-Type = '%s'\n", field_body_chars);
		int field_body_unfolded_length = strlen(field_body_chars);
		printf("      Unfolded body length: %d\n", field_body_unfolded_length);
		unsigned int semicolon_offsets[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
		int semicolon_count = 0;
		char* next_quote = NULL;
		char* next_semicolon = NULL;
		inside_quote = 0;
		for (int i = 0; i < field_body_unfolded_length; i++) {
			printf("      Current position: %p\n", field_body_chars + i);
			// memmem(&file_in_memory[position], sb.st_size - position, "\r", 1);
			next_quote = memmem(&field_body_chars[i], field_body_unfolded_length - i, "\"", 1);
			next_semicolon = memmem(&field_body_chars[i], field_body_unfolded_length - i, ";", 1);
			if (next_quote != NULL && next_semicolon != NULL && next_quote < next_semicolon) {
				printf("    Double-quote found at: %p (offset %d), skipping over\n", next_quote, (int)(next_quote - field_body_chars));
				next_quote = memmem(&next_quote[1], field_body_unfolded_length - (int)(next_quote - field_body_chars) , "\"", 1);
				if (next_quote != NULL) {
					printf("    Double-quote found at: %p (offset %d)\n", next_quote, (int)(next_quote - field_body_chars));
					i = (int)(next_quote - field_body_chars);
					continue;
				} else {
					printf("    Warning: Unmatched double-quote detected, reversing to offset %d\n", i);
				}
			}
			if (next_semicolon != NULL) {
				printf("        Semi-colon found at: %p (offset %d)\n", next_semicolon, (int)(next_semicolon - field_body_chars));
				semicolon_offsets[semicolon_count] = (int)(next_semicolon - field_body_chars);
				semicolon_count++;
				i = (int)(next_semicolon - field_body_chars);
			} else {
				break;
			}
		}
		printf("    Number of parameters: %d\n", semicolon_count);

		int mime_type_len = semicolon_count > 0 ? semicolon_offsets[0] : field_body_unfolded_length;
		unsigned char* mime_type = calloc(mime_type_len, sizeof(char));
		unsigned char* mime_subtype = calloc(mime_type_len, sizeof(char));
		if (mime_type_len > 0)
		{
			printf("    Parsing MIME type and subtype...\n");
			char* next_slash = memmem(&field_body_chars[0], mime_type_len, "/", 1);
			if (next_slash != NULL) {
				memcpy(mime_type, field_body_chars, (int)(next_slash - field_body_chars));
				printf("      MIME type: %s\n", mime_type);
			} else {
				memcpy(mime_type, field_body_chars, mime_type_len);
				printf("      MIME type: %s\n", mime_type);
			}
			if (semicolon_count > 0) {
				memcpy(mime_subtype, &next_slash[1], semicolon_offsets[0] - 1 - (int)(next_slash - field_body_chars));
				printf("      MIME subtype: %s\n", mime_subtype);
			} else {
				memcpy(mime_subtype, &next_slash[1], mime_type_len - 1 - (int)(next_slash - field_body_chars));
				printf("      MIME subtype: %s\n", mime_subtype);
			}
		}

		printf("    Indexing parameters... NOT FULLY IMPLEMENTED\n");

		int mime_parameter_len = 0;
		unsigned char* mime_param_name = calloc(field_body_unfolded_length + 1, sizeof(char));
		unsigned char* mime_param_value = calloc(field_body_unfolded_length + 1, sizeof(char));
		unsigned char* mime_boundary_delimiter = calloc(1000, sizeof(char));
		unsigned char* mime_charset = calloc(1000, sizeof(char));
		for (int i = 0; i < semicolon_count; i++)
		{
			mime_parameter_len = i + 1 < semicolon_count ? semicolon_offsets[i + 1] - semicolon_offsets[i] - 1 : field_body_unfolded_length - semicolon_offsets[i] - 1;
			printf("      Parameter length: %d\n", mime_parameter_len);
			char* next_equals = memmem(&field_body_chars[semicolon_offsets[i] + 1], mime_parameter_len, "=", 1);
			printf ("        Equals found at %p (offset %d)\n", next_equals, (int)(next_equals - field_body_chars) - semicolon_offsets[i]);
			if (next_equals != NULL) {
				size_t mime_param_name_len = (int)(next_equals - field_body_chars) - semicolon_offsets[i] - 1;
				memcpy(mime_param_name, &field_body_chars[semicolon_offsets[i] + 1], mime_param_name_len);
				printf("        Param name = '%s'\n", mime_param_name);
				size_t mime_param_value_len = mime_parameter_len - mime_param_name_len - 1;
				if (next_equals[1] == '"' && next_equals[mime_param_value_len] == '"') {
					printf("        Param value is a quoted-string\n");
					memcpy(mime_param_value, &next_equals[2], mime_param_value_len - 2);
				} else {
					memcpy(mime_param_value, &next_equals[1], mime_param_value_len);
				}
				printf("        Param value = '%s'\n", mime_param_value);
				if (strcasecmp("boundary", mime_param_name) == 0) {
					memcpy(mime_boundary_delimiter, &mime_param_value[0], mime_param_value_len);
					printf("        MIME boundary delimiter detected as '%s'\n", mime_boundary_delimiter);
				} else if (strcasecmp("charset", mime_param_name) == 0) {
					memcpy(mime_charset, &mime_param_value[0], mime_param_value_len);
					printf("        MIME charset detected as '%s'\n", mime_charset);
				}
			}
		}
		// memcpy(header_name_chars, &file_in_memory[line_start_offsets[i]], header_name_len);
		// header_name_chars[header_name_len + 0] = ':';
		// header_name_chars[header_name_len + 1] = '\0';
		//printf("%s\n", header_name_chars);

		// if (strcasecmp("return-path:", header_name_chars) == 0) {
		//      header_return_path[header_return_path_count] = i;
		//      header_return_path_count++;
		//      printf("  'return-path' trace header at index %d\n", i);

		if (strcasecmp("text", mime_type) == 0 && strcasecmp("plain", mime_subtype) == 0) {
			int print_body = 1;
			printf("----------\n");
			printf("  MIME type text/plain detected.\n");
			if (strcasecmp("UTF-8", mime_charset) == 0) {
				printf("  MIME charset UTF-8 detected. Checking locale...\n");
				char* locale_string = setlocale(LC_ALL, "");
				if (strcasecmp(".utf8", locale_string) >= 0 || strcasecmp(".UTF-8", locale_string)) {
					printf("    Locale includes '.utf8' or '.UTF-8'\n");
				}
			} else if (strlen(mime_charset) == 0) {
				printf("  MIME charset default (US-ASCII) assumed.");
			} else {
				print_body = 0;
				printf("  MIME charset %s detected.");
			}
			if (print_body == 1) {
				printf("  Printing message body to stdout...\n");
				printf("----------\n");
				for (int i = body_start; i < sb.st_size; i++)
				{
					char c = file_in_memory[i];
					printf("%c", file_in_memory[i]);
				}
				// TODO: Warn on non-compliant characters
				printf("\n");
			} else {
				printf("----------\n");
			}
		} else if (strcasecmp("multipart", mime_type) == 0) {
			printf("\n----------\n");
			printf("Multipart MIME message detected.\n");
			unsigned int boundary_offsets[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
			unsigned int boundary_terminator = 0;
			int boundary_count = 0;
			unsigned char* next_boundary = NULL;
			if (body_start > 0 && strlen(mime_boundary_delimiter) > 0) {
//			     printf("  MIME boundary parameter detected - rewinding start of message body by %d byte(s)...\n", line_ending_length);
//			     body_start -= line_ending_length;
//			     fseek(file_in_memory, body_start, SEEK_SET);
				printf("  Info: Current position: %d\n", body_start);
				printf("  Info: Indexing byte offsets of MIME boundary delimiters...\n  ");

				unsigned char* boundary_delim_chars = calloc(1000, sizeof(char));
				unsigned char* boundary_delim_end_chars = calloc(1000, sizeof(char));
				strcat(boundary_delim_chars, "--");
				strcat(boundary_delim_end_chars, "--");
				strcat(boundary_delim_chars, mime_boundary_delimiter);
				strcat(boundary_delim_end_chars, mime_boundary_delimiter);
				strcat(boundary_delim_end_chars, "--");
				int boundary_delim_chars_len = strlen(boundary_delim_chars);
				int boundary_delim_end_chars_len = strlen(boundary_delim_end_chars);
//			     printf("Boundary length: %d\n", boundary_delim_chars_len);
				unsigned char* next_line_separator = NULL;
				int current_line_length = 0;
				for (boundary_count = 0, position = body_start; position < sb.st_size; position++)
				{
					next_line_separator = memmem(&file_in_memory[position], sb.st_size - position, line_ending, line_ending_length);
					if (next_line_separator != NULL) {
						current_line_length = (int)(next_line_separator - file_in_memory - position);
/*
						if (current_line_length != 76) {
							printf("%d ", current_line_length);
						} else {
							printf (".");
						}
*/
						if (current_line_length == boundary_delim_chars_len) {
//						     printf("\nLine length matches boundary delim length at position %d\n", position);
//						     printf("%.*s\n", current_line_length, boundary_delim_chars);
//						     printf("%.*s\n", current_line_length, &file_in_memory[position]);
//						     int comparitor = memcmp(&file_in_memory[position], boundary_delim_chars, boundary_delim_chars_len);
//						     printf("%d\n", comparitor);
							if (memcmp(&file_in_memory[position], boundary_delim_chars, boundary_delim_chars_len) == 0) {
								next_boundary = file_in_memory + position;
								boundary_offsets[boundary_count] = position;
								printf("%6d ", position);
								boundary_count++;
								if (boundary_count %6 == 0) {
									printf("\n  ");
								}
							}
						} else if (current_line_length == boundary_delim_end_chars_len) {
							if (memcmp(&file_in_memory[position], boundary_delim_end_chars, boundary_delim_end_chars_len) == 0) {
								boundary_terminator = position;
								printf("\n  Info: Boundary delimiter termination at byte offset %d.\n", position);
							}

						}
						position += current_line_length;
					}
					//printf("Current position pointer: %p\n", &file_in_memory[position]);
				}
				printf("\n  Info: MIME boundary count = %d\n", boundary_count);
				printf("  Info: Current position: %d\n", position);

				int current_part = 0;
				for (current_part = 0; current_part < boundary_count; current_part++) {
					printf("\nParsing part #%d...\n", current_part);
					position = boundary_offsets[current_part] + boundary_delim_chars_len + line_ending_length;
					unsigned char* double_line_ending = memmem(&file_in_memory[position], sb.st_size - position, double_line_ending_chars, strlen(double_line_ending_chars));
					int header_length = double_line_ending - &file_in_memory[position];

					printf("--\n%.*s\n--\n", header_length, &file_in_memory[position]);
					printf("  Info: Content for part #%d starts at position %d\n", current_part, double_line_ending - file_in_memory + strlen(double_line_ending_chars));
					printf("  Info: Indexing byte offsets of header lines...\n  ");
					for (header_count = 0; position < double_line_ending - file_in_memory; position++)
					{
						next_line_ending = memmem(&file_in_memory[position], header_length - position, line_ending, line_ending_length);
						if (next_line_ending == NULL) {
							next_line_ending = double_line_ending;
						}
						if (valid_header_character(file_in_memory[position])) {
							line_start_offsets[header_count] = position;
							header_name_ending = memmem(&file_in_memory[position], header_length - position, ":", 1);
							//printf("header_name_ending: %p\n", &header_name_ending);
							if (next_line_ending == NULL || header_name_ending == NULL) {
								fprintf(stderr, "\nWarning: Line starting at byte %d does not contain both a colon and a line ending\n");
							}
							if (header_name_ending < next_line_ending) {
								header_name_lengths[header_count] = (int)(header_name_ending - &file_in_memory[position]) + 1;
								memcpy(header_name_chars, &file_in_memory[position], header_name_lengths[header_count]);
								//printf("header_name_lengths[%d] = %d\n", i, header_name_lengths[i]);
								//printf("  Info: Header #%d \"%s\" starting at byte offset %d\n", header_count, header_name_chars, position);
								printf("%6d ", position);
								bzero(header_name_chars, (MAX_HEADER_NAME_LENGTH + 1) * sizeof(char));
								header_count++;
								if (header_count %6 == 0) {
									printf("\n  ");
								}
							}
						}
						if (next_line_ending != NULL) {
							position = (int)(next_line_ending - &file_in_memory[0]);
						}
					}
					printf("\n\n  Info: Indexing specific headers...\n");
					int part_header_content_type[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
					int part_header_content_type_count = 0;
					int part_header_content_transfer_encoding[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
					int part_header_content_transfer_encoding_count = 0;
					int part_header_content_disposition[MAX_IDENTICAL_HEADER_COUNT] = { 0 };
					int part_header_content_disposition_count = 0;
					for (int i = 0; i < header_count; i++)
					{
						header_name_len = get_header_name_length(&file_in_memory[line_start_offsets[i]], header_name_lengths[i]);
						//printf("Header name length: %d\n", header_name_len);
						memcpy(header_name_chars, &file_in_memory[line_start_offsets[i]], header_name_len);
						header_name_chars[header_name_len + 0] = ':';
						header_name_chars[header_name_len + 1] = '\0';
						if (strcasecmp("content-type:", header_name_chars) == 0) {
							part_header_content_type[part_header_content_type_count] = i;
							part_header_content_type_count++;
							printf("    'content-type' header at index %d\n", i);
						} else if (strcasecmp("content-transfer-encoding:", header_name_chars) == 0) {
							part_header_content_transfer_encoding[part_header_content_transfer_encoding_count] = i;
							part_header_content_transfer_encoding_count++;
							printf("    'content-transfer-encoding' header at index %d\n", i);
						} else if (strcasecmp("content-disposition:", header_name_chars) == 0) {
							part_header_content_disposition[part_header_content_disposition_count] = i;
							part_header_content_disposition_count++;
							printf("    'content-disposition' header at index %d\n", i);
						} else {
							printf("    Unhandled header (%s) at index %d\n", header_name_chars, i);
						}
						bzero(header_name_chars, (MAX_HEADER_NAME_LENGTH + 1) * sizeof(char));
					}
	if (part_header_content_transfer_encoding_count == 1) {
		int header_index = part_header_content_transfer_encoding[0];
		bzero(field_body_chars, (MAX_HEADER_BODY_LENGTH + 1) * sizeof(char));
		printf("\nValidating Content-Transfer-Encoding header (does not support comments)...\n");
		line_start_offset = line_start_offsets[header_index];
		line_length = -1;
		if (header_index + 1 < header_count) {
			/* If there are subsequent headers, use the start of the next header and the start of this header to calculate line length */
			line_length = line_start_offsets[header_index + 1] - line_start_offset - line_ending_length;
		} else {
			/* If this is the last header, use the start of the part body and the start of this header to calculate line length */
			line_length = double_line_ending - &file_in_memory[line_start_offset];
		}
		//printf("  Line length: %d bytes\n", line_length);
		field_body_offset = line_start_offset + header_name_lengths[header_index];
		//printf("  field-body offset: %d bytes\n", field_body_offset);
		field_body_length = line_length - header_name_lengths[header_index];
		//printf("  field-body length: %d bytes\n", field_body_length);
		printf("  Parsing field-body...\n");
		for (int i = 0, pos = 0; pos < field_body_length; pos++)
		{
			unsigned char c = file_in_memory[field_body_offset + pos];
			//printf("%d = %d (%c)\n", i, c, c);
			if (c != '\r' && c != '\n' && c > 32 && c < 127) {
				memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
				if (c == '"') {
					inside_quote ^= 1;
					printf("    Inside Quoted-String: %s\n", inside_quote == 1 ? "true" : "false");
				}
				i++;
			} else if (inside_quote == 1 && (c == 32 || c == '\t')) {
				memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
				i++;
			}
//		     if (c > 47 && c < 58 || c == 46) {
//			     memcpy(&field_body_chars[i], &file_in_memory[field_body_offset + pos], 1);
//			     i++;
//		     }
		}
		int is_base64 = 0;
		printf("    Content-Transfer-Encoding = '%s'\n", field_body_chars);
		if (field_body_length == 7 && strncmp("base64", field_body_chars, 6) == 0) {
			int is_base64 = 1;
			printf("  Content-Transfer-Encoding validated as base64.\n");
			printf("  Extracting binary file...\n");
			printf("    current_part = %d, boundary_count = %d, next_offset = %p, termination = %p, double_line_ending = %p\n", current_part, boundary_count, &file_in_memory[boundary_offsets[current_part + 1]], &file_in_memory[boundary_terminator], double_line_ending);
			int content_length = current_part + 1 < boundary_count ? &file_in_memory[boundary_offsets[current_part + 1]] - double_line_ending - line_ending_length - line_ending_length : &file_in_memory[boundary_terminator] - double_line_ending - line_ending_length - line_ending_length;
			unsigned char* first_byte = double_line_ending + line_ending_length + line_ending_length;
			unsigned char* encoded_bytes = calloc(content_length + 1, sizeof(char));
			int raw_base64_length = 0;
			int pos = 0;
			for (raw_base64_length = 0, pos = 0; pos < content_length; pos++) {
				unsigned char c = first_byte[pos];
				if (c != '\n' && c != '\r') {
					memcpy(&encoded_bytes[raw_base64_length], first_byte + pos, 1);
					raw_base64_length++;
				}
			}
			printf("    Detected Content-Length: %d bytes (%d bytes without newlines)\n", content_length, raw_base64_length);
			int *output_length = calloc(1, sizeof(int));
			unsigned char* decoded_bytes = base64_decode(encoded_bytes, raw_base64_length, output_length);
			if (decoded_bytes != NULL) {
				printf("    Decoded content length: %d bytes\n", *output_length);
				unsigned char* sha1_digest = sha1_hash(decoded_bytes, *output_length);
				printf("    SHA-1 Hash: %s\n", sha1_digest);
				// Try to open the file
				errno = 0;
				unsigned char base64_output_path[2048];
				sprintf(base64_output_path, "/tmp/%s", sha1_digest);
				free(sha1_digest);
				FILE *fd_base64 = fopen(base64_output_path, "w");
				if (fd_base64 == NULL) {
					perror("open() error: ");
				} else {
					size_t bytes_written = fwrite(decoded_bytes, 1, *output_length, fd_base64);
					if (bytes_written != *output_length) {
						fprintf(stderr, "File write byte length mismatch: %d written, %d expected\n", bytes_written, output_length);
					} else {
						printf("  Extracted file to %s\n", base64_output_path);
					}
					fclose(fd_base64);
				}
				free(decoded_bytes);
			}
		}
	}

				}
			}

			// if (strncmp("1.0", field_body_chars, 3) == 0) {
			//      is_mime_v1 = 1;
			//      printf("  MIME-Version field-body validated.\n");
			// }

			if (mime_param_name != NULL) {
				free(mime_param_name);
				mime_param_name = NULL;
			}
			if (mime_param_value != NULL) {
				free(mime_param_value);
				mime_param_value = NULL;
			}
		}
	}

	// // TODO: Create functions for parsing different field-body types
	// // TODO: Improve parsing of a content-type header field-body
	// if (strlen(current_header_value) > 0) {
	//      // Print the field-body
	//      printf("%s\n", current_header_value);
	//      // Find the first semi-colon in the content-type header's field-body
	//      // TODO: A missing semi-colon is not handled correctly
	//      char* first_semicolon = strstr(current_header_value, ";");
	//      int first_semicolon_index = first_semicolon - current_header_value;
	//      if (strncmp("text/plain", current_header_value, first_semicolon_index) == 0) {
	//	      // If content-type is text/plain, print to stdout
	//	      // TODO: Handle different character sets
	//	      printf("text/plain detected, printing message body to stdout...\n\n");
	//	      for (int i = body_start; i < sb.st_size; i++)
	//	      {
	//		      c = file_in_memory[i];
	//		      printf("%c", file_in_memory[i]);
	//	      }
	//	      printf("\n");
	//      }
	// }

/*     if (header_name_chars != NULL) {
		free(header_name_chars);
		header_name_chars = NULL;
	}
	if (double_line_ending_chars != NULL) {
		free(double_line_ending_chars);
		double_line_ending_chars = NULL;
	}
	if (line_ending != NULL) {
		free(line_ending);
		line_ending = NULL;
	}*/

// TODO: Warn on non-compliant characters
// TODO: Do headers require a field-body?
// TODO: Warn on invalid characters in header field-bodies
// TODO: Can header field-names be folded?
// TODO: Check maximum length of field-name, for now assuming (strlen(field-name + colon) <= 997) characters
// TODO: Sanity check the number of content-type headers, and warn if there is a potential issue
// TODO: Do the RFCs say how differing headers with the same field-name should be treated?
// TODO: Do the RFCs say a field-name should be followed by : and SP? strlen(": ") is the '+ 2' at end of offset calculation


	// if (mime_version_header_count == 0) {
	//      printf("Info: No MIME-Version header.\n");
	// } else if (mime_version_header_count > 1) {
	//      fprintf(stderr, "Warning: More than one (%d) MIME-Version header detected.\n", mime_version_header_count);
	// } else {
	//      printf("Info: MIME-Version header value is: ");
	// }

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
