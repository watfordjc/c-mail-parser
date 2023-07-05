# mail-parser

mail-parser is a WIP command-line utility with the goal of parsing Maildir-stored e-mail files.

The early versions of the program will use parsing code written from scratch to familiarise myself with the e-mail and related RFCs that specify how e-mails should be interpreted.

Later versions may rely on a library to handle some of the parsing.

## Goals

- [x] ```mmap``` (as read-only) the file specified in a command-line argument.
- [x] Index the line-endings of headers and where the message body (if any) begins.
- [x] Print the header names.
- [ ] Parse the MIME-Version header.
- [x] Parse the Content-Type header.
- [ ] Print the body if there is no Content-Type header.
- [x] Print the body if ```Content-Type: text/plain```.
- [ ] Parse the first level of ```Content-Type: multipart/alternative``` and index the boundary delimiters.
- [ ] Parse nested levels of multipart MIME message bodies.

## Compiling

The current source code should compile with gcc if the necessary C libraries are available:

```bash
gcc c-mail-parser.c -o mail-parser
```

## Usage

The current code creates a program that requires one argument: a single e-mail file to parse.

```bash
./mail-parser path/to/email-message-file
```

As the program is being designed for files stored in Maildir format mailboxes, on Linux systems where the LDA is dovecot, files with lines terminated by ```LF``` will likely be better tested than those with ```CRLF``` line endings.

