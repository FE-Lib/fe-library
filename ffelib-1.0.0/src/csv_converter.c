/***********************************************************************
 * File: csv_converter.c
 * 	(Extracted from
 *	   "$Id: csv_converter.c,v 1.4 2009/05/30 14:11:51 maoyam Exp maoyam $")
 *
 * Abstracts:
 *  This C source code implements the converter for the CSV/TSV-files.
 *
 * Copyright (C) 2004-2007 Maoyam Tokyo, Japan (mailto:maoyam@mail.goo.ne.jp)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 **********************************************************************/


/* include definitions */
#include "csv_converter.h"

/* Definitions of the CSV tokens */
#define EOS				'\0'
#define DQ				'"'
#define CR				'\r'
#define LF				'\n'
#define TAB				DLMT_TAB
#define CO				DLMT_COMMA
#define CR_LF_SEQ		"\r\n"
#define	CR_LF_SEQ_LEN	2

#define ISCH(C) (			\
		(char)(C) != EOS	\
		&& (char)(C) != CO	\
		&& (char)(C) != DQ	\
		&& (char)(C) != CR	\
		&& (char)(C) != LF	\
	)

/* Definitions for allocating memories */
#define MIN_CSV_STRING_AREA_SZ (CR_LF_SEQ_LEN + 1)
#define GET_MAX_SZ_OF_CSV_STR(CSTR) (					\
			(strlen((const char *)(CSTR)) * 2) + 2 + 1	\
		)


/* Convert a C-string to a CSV-string */
char *string_to_csv_string(const char	*string
							, char		*csv
							, size_t	*csv_str_sz
							)
{
	char	*csvp = NULL;

	errno	= 0; /* initialize errno */

	/* check the argument is legal? */
	if ((string != NULL) || csv_str_sz == NULL) {
		size_t	csv_len = (size_t)0, csv_max_sz = (size_t)0;
		char	*c_str = NULL;	/* C-string pointer */
		char	*new_csv;
		size_t	need_enclose_DQ = (size_t)0;
					/* non-zero means that CSV-string needs to encapsulate
					 * with double-quote characters
					 */

		/* check the CSV-string area wasn't allocated, yet?
		 * nor, the allocated are size is greater than CSV-string maximum
		 * size?
		 */
		if (csv == NULL) {
			/* get the maximum size of the CSV-string area */
			*csv_str_sz = GET_MAX_SZ_OF_CSV_STR(string);

			/* allocate the new CSV-string area */
			if ((new_csv = (char *)malloc(*csv_str_sz)) == NULL) {
				/* !!FATAL!! Can't allocate the new CSV-string area!  */
#				if defined(DEBUG) /* { */
					fprintf(stderr
							,	"!!FATAL!! "
								"string_to_csv_string(%p, %p, %p) "
								"can't allocate memory of the CSV-string. "
								"{csv_str_sz = %lu, csv = %p}\n"
							, string, csv, (void *)csv_str_sz
							, (unsigned long)(*csv_str_sz), csv
							);
#				endif /* } defined(DEBUG) */

				return	NULL;	/* failed in malloc(3C):
								 * (errno should be ENOMEM or EAGAIN)
								 */
			}
			csv	= new_csv;
		}
		else if ((csv_max_sz = GET_MAX_SZ_OF_CSV_STR(string))
														> *csv_str_sz
		) {	/* re-allocate the CSV-string area to extend for `csv_max_sz'
			 * size
			 */
			if ((new_csv = (char *)realloc(csv, csv_max_sz)) == NULL) {
				/* !!FATAL!! Can't re-allocate the CSV-string of
				 * `csv_max_sz'!
				 */
#				if defined(DEBUG) /* { */
					fprintf(stderr
							,	"!!FATAL!! "
								"string_to_csv_string(%p, %p, %p) "
								"can't allocate memory can't re-allocate "
								"memory of the CSV-string. "
								"{csv_str_sz = %lu, csv = %p}\n"
							, string, csv, (void *)csv_str_sz
							, (unsigned long)*csv_str_sz, csv
							);
#				endif /* } defined(DEBUG) */

				return	NULL;	/* failed in realloc(3C):
								 * (errno should be ENOMEM or EAGAIN)
								 */
			}
			csv	= new_csv;

			/* set the size of CSV-string area that is re-allocated */
			*csv_str_sz	= csv_max_sz;
		}
		else {
			; /* we can use the CSV-string for converting */
		}

		/* initialize the CSV-string area with the null characters */
		memset(csv, (int)EOS, *csv_str_sz);

		/* loop for converting the C-string to CSV-string... */
		c_str	= (char *)string; /* initialize the C-string pointer */
		csvp	= csv; /* save the address */
		while (csv_len < *csv_str_sz) {
			/* definitions to convert the C-string to the CSV-string */
			if (*c_str == EOS) {
				/* reached End Of String character */
				*csv++	= EOS; ++csv_len;
				csv = csvp; /* restore the address */

				break; /* finished to process the C-string argument now, 
						* the C-string is pointing to EOS character
						*/
			}
			else if (*c_str == CR) {
				/* process "CR"/"CR-LF" sequence */
				/* We must encapsulate this CSV-string with DQ, later! */
				++need_enclose_DQ;

				/* check this sequence is "CR" only or "CR-LF"? */
				if (*(c_str + 1) != LF) {
					/* "CR" only ==> replace CR to LF */
					*csv++	= LF; ++csv_len;
					++c_str;
				}
				else { /* "CR-LF" sequence */
					/* skip Carriage Return character */
					++c_str;
				}
			}
			else if (*c_str == DQ) {
				/* process a Double Quote */
				/* We must encapsulate this CSV-string with DQ, later! */
				++need_enclose_DQ;

				*csv++	= DQ; *csv++ = DQ;
				csv_len += 2; ++c_str;
			}
			else { /* process other characters (includes Comma & LF) */
				/* check the source character isn't usual character? */
				if (!ISCH(*c_str)) {
					/* We must enclose this CSV-string with DQ! */
					++need_enclose_DQ;
				}

				*csv++	= *c_str++; ++csv_len;
			}
		}

		/* check the converting loop finished completely, and then,
		 * the left size of the CSV-string area is 2 bytes or more?
		 */
		if ((*c_str == EOS)
		|| *csv_str_sz - csv_len >= CR_LF_SEQ_LEN
		) {	/* check this CSV-string needs to be encapsulated with DQ? */
			if (need_enclose_DQ != 0) {
				/* insert Double Quotation at head and tail of
				 * the CSV-string
				 */
				memmove(csvp + 1, csvp, csv_len);
				*csvp	= DQ; *(csvp + csv_len) = DQ;
				csv_len += 2;
			}
		}
		else {	/* !!FATAL!! Internal Error! failed in converting loop */
#			if defined(DEBUG) /* { */
				fprintf(stderr
						,	"!!FATAL!! "
							"string_to_csv_string(%p, %p, %p) "
							"can't allocate occurred an internal error! "
							"{*c_str = 0x%x, *csv_str_sz = %lu, "
							"csv_len = %lu, "
							"*csv_str_sz - csv_len = %lu}\n"
						, string, csv, (void *)csv_str_sz
						, *c_str, (unsigned long)(*csv_str_sz)
						, (unsigned long)csv_len
						, (unsigned long)(*csv_str_sz - csv_len)
						);
#			endif /* } defined(DEBUG) */

			/* release the all allocated memories */
			free(csvp);
			csv	= csvp = NULL;
			*csv_str_sz	= (size_t)0;

			/* Internal Error in converting */
			return (char *)(-1);
		}
	}
	else {
		return	NULL; /* The argument is illegal! */
	}

	return	csv; /* returns the address pointing to CSV-string */
}

/* convert a C-string to the CSV-string, and append it to CSV-line area */
static char *append_string_to_csv_line(const char	*string
										, char		**csv
										, size_t	*csv_sz
										, char		*csv_line
										)
{
	char	*csvp = *csv; /* save the address */

	/* check the C-string is NULL? */
	if (string == NULL) {
		string	= ""; /* force to convert the empty C-string */
	}

	/* try to convert the C-string to the CSV-string */
	if ((*csv = string_to_csv_string(string, *csv, csv_sz)) != NULL) {
		/* append the CSV-string that is converted from the C-string,
		 * to the CSV-line area
		 */
		strcat(csv_line, *csv);
	}
	else { /* failed to convert the C-string to CSV-string */
		/* check the CSV-string buffer was allocated, yet? */
		if (csvp != NULL) {
			free(csvp); /* release the CSV-string buffer */
		}
		*csv = NULL; *csv_sz = (size_t)0;	/* set zero size the area */

		return	NULL; /* failed in converting this C-string */
	}

	return	csv_line; /* returns the address to the CSV-line */
}

/* Convert an array of C-strings to a CSV-line */
char *strings_to_csv_line(char		*strings[]
						, int		n
						, char		*csv_line
						, size_t	*csv_line_sz
						, char		delimit /* DLMT_COMMA or DLMT_TAB */
						)
{
	size_t	csv_line_max_sz = (size_t)0, csv_sz = (size_t)0;
	char	*csv = NULL;
	char	*new_csv_line;
	int		i;

	errno	= 0; /* initialize errno */

	/* check the array of C-strings and the count of it are illegal,
	 * nor the delimiter is illegal?
	 */
	if (((strings == NULL)
	|| n < 0)
	|| strchr(DLMT_FORBIDDEN_CHARS, delimit) != NULL
	) {	return	NULL;	/* returns NULL; illegal arguments */	}

	/* get the maximum size of this CSV-line from the C-string array */
	for (csv_line_max_sz = 1, i = 0; i < n; ++i) {
		if (strings[i] != NULL) {
			csv_line_max_sz	+= GET_MAX_SZ_OF_CSV_STR(strings[i]);
		}
	}

	/* add the size of "CR-LF" sequence */
	csv_line_max_sz	+= CR_LF_SEQ_LEN;

	/* check the CSV-line area wasn't allocated, yet? */
	if (csv_line == NULL) {
		/* allocate the maximum size of this CSV-line area */
		if ((new_csv_line = (char *)malloc(csv_line_max_sz)) == NULL) {
			/* !!FATAL!! Can't allocate the CSV-line area */
#			if defined(DEBUG) /* { */
				fprintf(stderr
						,	"!!FATAL!! "
							"strings_to_csv_line(%p, %d, %p, %p, 0x%x) "
							"can't allocate memory for the CSV-line. "
							"(csv_line_max_sz = %lu, "
							"csv_line = %p)\n"
						, (void *)strings, n, csv_line, (void *)csv_line_sz
						,										delimit
						, (unsigned long)csv_line_max_sz
						, csv_line
						);
#			endif /* } defined(DEBUG) */

			return NULL;	/* can't allocate CSV-line area:
							 * (`errno' should be ENOMEM or EAGAIN)
							 */
		}
		csv_line	= new_csv_line;

		/* set the size of this CSV-line area */
		*csv_line_sz	= csv_line_max_sz;
	}
	else if (*csv_line_sz < csv_line_max_sz) {
		/* re-allocate the CSV-line area for the maximum size */
		if ((new_csv_line = (char *)realloc(csv_line, csv_line_max_sz))
																== NULL
		) {	/* !!FATAL!! Can't re-allocate the CSV-line area */
#			if defined(DEBUG) /* { */
				fprintf(stderr
						,	"!!FATAL!! "
							"strings_to_csv_line(%p, %d, %p, %p, 0x%x) "
							"can't re-allocate memory for the CSV-line. "
							"(csv_line_max_sz = %lu, csv_line = %p)\n"
						, (void *)strings, n, csv_line, (void *)csv_line_sz
						,										delimit
						, (unsigned long)csv_line_max_sz, csv_line
						);
#			endif /* } defined(DEBUG) */

			return NULL;	/* can't re-allocate CSV-line area:
							 * `errno' should be ENOMEM or EAGAIN
							 */
		}
		csv_line	= new_csv_line;

		*csv_line_sz = csv_line_max_sz; /* set the size of this CSV-line */
	}
	else {
		; /* we can use this CSV-line area for converting */
	}

	/* initialize the CSV-line area */
	memset(csv_line, (int)'\0', *csv_line_sz);

	/* check the array of C-string isn't empty? */
	if (n > 0) { /* convert the C-strings to a CSV-line */
		/* initialize several variables for converting the each C-strings
		 */
		csv	= NULL; csv_sz	= (size_t)0; i = 0;

		/* convert the 1st C-string and append the converted result
		 * to CSV-line
		 */
		if (append_string_to_csv_line(strings[i], &csv, &csv_sz, csv_line)
																== NULL
		) {	/* !!FATAL!! failed in converting the 1st C-string */
			return	NULL;
		}

		/* loop for converting the rest of C-strings... */
		while (++i < n) {
			/* append the field delimiter (Comma character), convert the
			 * C-string, and then, append the converted result to CSV-line
			 */
			size_t	len = strlen(csv_line);
			csv_line[len] = delimit; csv_line[len + 1] = EOS;
			if (append_string_to_csv_line(strings[i]
										, &csv
										, &csv_sz
										, csv_line
										) == NULL
			) {/* !!FATAL!! failed in converting the C-strings */
				return	NULL;
			}
		}

		/* release the allocated `csv' (that was appended to `csv_line') */
		if (csv != NULL) {	free(csv);	}
	}

	/* append "CR-LF" sequence to the CSV-line, and then,
	 * returns the address pointing to the allocated CSV-line area
	 */
	return	strcat(csv_line, CR_LF_SEQ);
}

/* read a CSV line, that terminates with CR-LF sequence, from a stream. */
char *get_csv_line(FILE		*stream
				, char		*csvl
				, size_t	*csvlsz
				, int		*is_broken
				)
{
	size_t	read_sz;
	char	*new_csvl = NULL, *p = csvl, *last_byte = NULL;

	errno	= 0; /* initialize errno */

	/* check the arguments are illegal? */
	if (((stream == NULL) || csvlsz == NULL) || is_broken == NULL) {
		return	NULL;	/* ERROR: illegal arguments */
	}

	*is_broken	= 0; /* initialize `is_broke' to false (== 0) */

	/* check the CSV-line area is NULL? */
	if (csvl == NULL) {
		/* allocate the area that has default size */
		if ((new_csvl = (char *)malloc(DEFAULT_CSV_LINE_SZ)) == NULL) {
			/* FATAL! can't allocate the CSV-line area (default size) */
#			if defined(DEBUG) /* { */
				fprintf(stderr
						,	"!!FATAL!! "
							"get_csv_line(%p, %p, %p, %p): "
							"can't allocate the CSV-line area "
							"(default size = %lu)\n"
						, (void *)stream, csvl, (void *)csvlsz
						,								(void *)is_broken
						, (unsigned long)DEFAULT_CSV_LINE_SZ
						);
#			endif /* defined(DEBUG) } */

			return	NULL;	/* FATAL: can't allocate the default size
							 * CSV-line area.
							 *  (`errno' should be ENOMEM or EAGAIN)
							 */
		}
		csvl	= new_csvl;

		*csvlsz	= DEFAULT_CSV_LINE_SZ; /* set the size of allocated area */
	}

	memset(csvl, (int)EOS, *csvlsz); /* clear the CSV-line area */

	/* loop for read a CSV-line, and store the characters to `csvl' area...
	 */
	p	= csvl; read_sz = 0;
	while ((last_byte = fgets(p, (int)(*csvlsz - (p - csvl)), stream))
																!= NULL
	) {	/* get the last read size, and sum the total size of this CSV-line.
		 */
		size_t	sz = strlen(p);
		read_sz	+= sz;

		/* check the CSV-line terminator is read, at last? */
		if ((read_sz >= CR_LF_SEQ_LEN)
		&& strcmp(p + (sz - CR_LF_SEQ_LEN), CR_LF_SEQ) == 0
		) {	break; /* reached end of CSV-line */	}

		/* check the `csvl' area is filled? */
		if (*csvlsz - 1 == read_sz) {
			char	*clp;

			/* re-allocate the CSV-line area to extend the size */
			if ((clp = (char *)realloc(csvl
									, (*csvlsz + DEFAULT_CSV_LINE_SZ))
									) == NULL
			) {	/* FATAL! can't re-allocate the CSV-line area for extending
				 * its size
				 */
#				if defined(DEBUG) /* { */
					fprintf(stderr
						,	"!!FATAL!! "
							"get_csv_line(%p, %p, %p, %p): "
							"can't re-allocate the CSV-line area "
							"(read_sz = %lu, *csvlsz = %lu, "
							"extend size = %lu, delta = %lu)\n"
						, (void *)stream, csvl, (void *)csvlsz
						,							(void *)is_broken
						, (unsigned long)read_sz
						,					(unsigned long)*csvlsz
						, (unsigned long)(*csvlsz + DEFAULT_CSV_LINE_SZ)
						,				(unsigned long)DEFAULT_CSV_LINE_SZ
						);
#				endif /* defined(DEBUG) } */

				/* release the CSV-line buffer that was allocated */
				free(csvl); *csvlsz = 0;

				return NULL;	/* FATAL: can't re-allocate the CSV-line
								 * area for extending its size.
								 *  (`errno' should be ENOMEM or EAGAIN)
								 */
			}

			/* set the address of the extended CSV-line buffer, and update
			 * the size of CSV-line area
			 */
			csvl = clp; *csvlsz += DEFAULT_CSV_LINE_SZ;
		}

		p = csvl + read_sz; /* set the pointer to the next read-in byte */
	}

	/* check the stream reached EOF and read something? */
	if (last_byte == NULL) {
		if (read_sz > (size_t)0) {
			/* the last read-in line doesn't terminate with CR-LF sequence.
			 * thus, set `is_broken' true (== 1).
			 */
			*is_broken	= 1;
		}
		else { /* reached EOF of this CSV-file, yet */
			/* release the CSV-line buffer, and set buffer size to be zero
			 */
			free(csvl); csvl = NULL; *csvlsz = (size_t)0;
		}
	}

	return	csvl;	/* returns the address of the CSV-line
					 * (it terminates with the CR-LF sequence)
					 */
}

/* convert a CSV-line to the vector of C-strings */
char **csv_line_to_strings(char	*csvl
						, char	delimitch
						, int	*colscnt
						)
{
	char **strings = NULL, *csvp = csvl, *strp = csvl, **new_strings;
	int	in_quoted = 0;

	/* initialize the count of columns */
	*colscnt	= 0;

	/* allocate the pointer to pointer `strings' */
	if ((new_strings = (char **)malloc(sizeof(*strings))) == NULL) {
		/* !!FATAL!! can't allocate the vector of C-strings */
#		if defined(DEBUG) /* { */
			fprintf(stderr
				,	"!!FATAL!! "
					"csv_line_to_strings(%p, '%c', %p): "
					"can't allocate the vector of C-string. "
					"(sizeof(*strings) = %lu)\n"
				, csvl, delimitch, (void *)colscnt
				, (unsigned long)sizeof(*strings)
				);
#		endif /* } defined(DEBUG) */

		return	NULL;	/* !!FATAL!! returns NULL.
						 * (`errno' should be ENOMEM or EAGAIN)
						 */
	}
	strings	= new_strings;

	/* loop for processing the CSV-line until reached CR-LF ... */
	/* set the 1st column address */
	strings[*colscnt] = strp; ++(*colscnt);
	while ((*csvp != EOS) && strcmp(csvp, CR_LF_SEQ) != 0) {
		/* definition how to parse the CSV-line */
		if ((in_quoted == 0) && *csvp == delimitch) {
			/* now, we had seen the delimiter */
			/* terminate the C-string ('\0'), proceed the next CSV-column
			 */
			*strp	= '\0'; strp = ++csvp;

			/* re-allocate the vector of C-strings to extend it */
			if ((new_strings = (char **)
							realloc(strings
									, (sizeof(*strings) * (*colscnt + 1))
									)) == NULL
			) {	/* FATAL!! can't re-allocate the vector of C-strings */
#				if defined(DEBUG) /* { */
					fprintf(stderr
						,	"!!FATAL!! "
							"csv_line_to_strings(%p, '%c', %p): "
							"can't re-allocate the vector of C-strings. "
							"(*colscnt = %d, "
							"sizeof(*strings) * (*colscnt) = %lu)\n"
						, csvl, delimitch, (void *)colscnt
						, *colscnt
						, (unsigned long)(sizeof(*strings) * (*colscnt))
						);
#				endif /* } defined(DEBUG) */

				/* release the allocated buffer and be zero counter */
				free(strings); *colscnt = 0;

				return	NULL;	/* returns NULL.
								 * (`errno' should be ENOMEM or EAGAIN)
								 */
			}
			strings	= new_strings;

			/* set the next column address */
			strings[*colscnt] = strp; ++(*colscnt);
		}
		else if (*csvp == DQ) { /* see Double Quotation? */
			++csvp;	/* see the next character... */

			/* check we see the not-quoted characters? */
			if (in_quoted == 0) {
				++in_quoted; /* begin the quoting sequence! */
			}
			else { /* see the quoted characters... */
				/* check the DQ-DQ sequence? */
				if (*csvp == DQ) {
					/* see the DQ-DQ sequence */
					/* set a Double Quotation character to C-string. */
					*strp++	= DQ; ++csvp;
				}
				else {
					--in_quoted; /* reached the end of the quoting! */
				}
			}
		}
		else { /* see the usual characters */
			*strp++	= *csvp++;
		}
	}

	/* terminate the last C-string ('\0'), and increase the column count */
	*strp	= '\0';

	return	strings; /* returns the vector of C-strings */
}

/* release the memory blocks that `parse_csv_file()" allocated. */
void free_parsed_csv_t(Parsed_CSV_t *parsed)
{
	errno	= 0; /* initialize errno */

	if (parsed == NULL) {	return;	/* released this, yet */	}

	/* check the areas pointed from argument isn't released, yet? */
	if (parsed->lines != NULL) {
		Parsed_CSV_Line_t	*linep = NULL;
		int					i;

		/* loop for the each CSV-line structures... */
		for (i = 0; i < parsed->line_cnt; ++i) {
			/* set the address of a CSV-line structure */
			linep	= parsed->lines[i];

			/* check this CSV-line structure isn't released, yet? */
			if (linep != NULL) {
				/* check the vector of the CSV-line columns pointers
				 * isn't released, yet?
				 */
				if (linep->cols != NULL) {
					free(linep->cols); /* release the memory block */
				}

				/* initialize the vector pointer and the count of columns
				 */
				linep->cols = NULL; linep->cols_cnt = 0;

				/* check the buffer of CSV-line isn't released, yet? */
				if (linep->linebuf != NULL) {
					free(linep->linebuf); /* release the memory block */
				}

				/* initialize the buffer pointer and the size of buffer */
				linep->linebuf = NULL; linep->linebuf_sz = (size_t)0;

				free(linep); /* release the allocated structure */
			}

			/* initialize the CSV-line structure pointer */
			parsed->lines[i]	= NULL;
		}

		/* release the vector of the CSV-line structures */
		free(parsed->lines);

		/* initialize the count of minimum and maximum count of
		 * CSV-line columns, and initialize the count of the CSV-lines
		 */
		parsed->min_cols_cnt	= parsed->max_cols_cnt	= 0;
		parsed->lines			= NULL;
		parsed->line_cnt		= 0;
	}

	return; /* no value */
}

/* parse the CSV/TSV formatted file */
Errcode_Parse_CSV_File_t parse_csv_file(const char		*path
										, char			delimit
										, Parsed_CSV_t	*parsed
										)
{
	Errcode_Parse_CSV_File_t	result = EPCF_NORMAL_END;
	Parsed_CSV_Line_t			*linep, *new_line;
	size_t						csv_line_sz = (size_t)0;
	FILE						*fp = NULL;
	char						*r = NULL, *csv_line = NULL;
	int							is_broken = 0;

	errno	= 0; /* initialize errno */

	/* check the parameters */
	if ((path == NULL) || parsed == NULL) {
		return	EPCF_Null_Pointer_Para;
	}
	if (strchr(DLMT_FORBIDDEN_CHARS, delimit) != NULL) {
		return	EPCS_Illegal_Delimiter;
	}
	if (access(path, (F_OK | R_OK)) != 0) {
		return	EPCF_Not_Readable_File;
	}

	/* open the CSV/TSV file */
	if ((fp = fopen(path, "r")) == NULL) {
		return	EPCF_Cannot_Open_File;
	}

	/* initialize the result area `parsed' */
	parsed->line_cnt		= 0;
	parsed->lines			= NULL;
	parsed->min_cols_cnt	= parsed->max_cols_cnt	= 0;

	/* loop for processing the CSV/TSV file... */
	while ((r = get_csv_line(fp, NULL, &csv_line_sz, &is_broken)) != NULL)
	{
		Parsed_CSV_Line_t	**lines, **new_lines;
		char				**new_cols;

		/* set the CSV-line buffer */
		csv_line	= r;

		/* extend the vector of CSV-line structure */
		if ((new_lines = (Parsed_CSV_Line_t **)
							realloc(parsed->lines
									, (sizeof(parsed->lines[0])
												* (parsed->line_cnt + 1))
									)) == NULL
		) {	/* FATAL!! failed in re-allocate the vector of CSV-line
			 * structures
			 */
#			if defined(DEBUG) /* { */
				fprintf(stderr
				,	"!!FATAL!! "
					"parse_csv_file(%p, 0x%x, %p) "
					"can't re-allocate the vector of CSV-line structures "
					"(parsed->lines = %p, "
					"sizeof(parsed->lines[0]) = %lu, "
					"parsed->line_cnt = %d)\n"
				, path, delimit, (void *)parsed
				, (void *)(parsed->lines)
				, (unsigned long)sizeof(parsed->lines[0])
				, parsed->line_cnt
				);
#			endif /* } defined(DEBUG) */

			/* decrease the count of CSV-line structures, and then,
			 * release the all areas those were allocated, yet
			 */
			free_parsed_csv_t(parsed);

			free(csv_line); /* release the last read-in buffer */

			/* set the error code, and break this loop */
			result	= EPCF_Cannot_Reallocate_Parsed_CSV_t_Lines_Vector
			; break
			;
		}
		lines	= new_lines;

		/* set the address of the vector for the CSV-line structures */
		parsed->lines = lines;
		parsed->lines[parsed->line_cnt]	= NULL;

		/* allocate the new CSV-line structure */
		if ((new_line = (Parsed_CSV_Line_t *)
							malloc(sizeof(*(parsed->lines[0])))) == NULL
		) {	/* FATAL!! failed in allocate the CSV-line structure */
#			if defined(DEBUG) /* { */
				fprintf(stderr
					,	"!!FATAL!! "
						"parse_csv_file(%p, 0x%x, %p) "
						"can't allocate the CSV-line structure "
						"(parsed->lines = %p, "
						"parsed->line_cnt = %d, "
						"sizeof(parsed->lines[0]) = %lu)\n"
					, path, delimit, (void *)parsed
					, (void *)(parsed->lines)
					, parsed->line_cnt
					, (unsigned long)sizeof(parsed->lines[0])
					);
#			endif /* } defined(DEBUG) */

			/* release the all areas those were allocated, yet */
			free_parsed_csv_t(parsed);

			free(csv_line); /* release the last read-in buffer */

			/* set the error code, and break this loop */
			result	= EPCF_Cannot_Allocate_Parsed_CSV_Line_t
			; break
			;
		}

		/* set the size of CSV-line buffer and the address of it, and
		 * initialize the count of the CSV-line columns and the address
		 * of the vector for CSV-line columns
		 */
		linep				= new_line;
		linep->linebuf_sz	= csv_line_sz;
		linep->linebuf		= csv_line;
		linep->cols_cnt		= 0;
		linep->cols 		= NULL;

		/* set the pointer to the allocated Parsed_CSV_Line_t structure
		 * to the last slot of Parsed_CSV_t's lines vector
		 */
		parsed->lines[parsed->line_cnt] = linep; ++(parsed->line_cnt);

		/* convert the CSV-line buffer to the CSV-line structure */
		if ((new_cols = csv_line_to_strings(csv_line
											, delimit
											, &(linep->cols_cnt))) == NULL
		) {	/* Failed in converting the CSV-line buffer! */
			if (errno == ENOMEM || errno == EAGAIN) {
				/* Failed in allocating the memories! */
				free_parsed_csv_t(parsed); /* release all areas */
				result	= EPCF_Cannot_Allocate_Memory;
			}
			else { /* Internal Error; processing the CSV-line buffer */
				result	= EPCF_Failed_Convert_CSV_Line;
			}

			break; /* this loop */
		}
		linep->cols	= new_cols;

		/* check the minimum count of CSV-line columns is illegal? */
		if (parsed->min_cols_cnt > linep->cols_cnt) {
			/* update the minimum count */
			parsed->min_cols_cnt	= linep->cols_cnt;
		}

		/* check the maximum count of CSV-line columns is illegal? */
		if (parsed->max_cols_cnt < linep->cols_cnt) {
			/* update the maximum count */
			parsed->max_cols_cnt	= linep->cols_cnt;
		}

		/* check the CSV-line is broken? */
		if (is_broken != 0) {
			result	= EPCF_Broken_CSV_File;
			break; /* ERROR: the CSV-file contains a broken line */
		}
	}

	/* check the size of CSV-file is zero? */
	if (r == NULL && csv_line == NULL && csv_line_sz == (size_t)0) {
		result	= EPCF_Zero_Size_File; /* set the error code */
	}

	/* close the CSV-file */
	(void)fclose(fp);
		
	return	result; /* the error code of this CSV-file parser */
}

/* this returns the address pointing to the value of a CSV field */
char *get_value_parsed_csv_t(Parsed_CSV_t *pcp, int row, int col)
{
	errno	= 0; /* initialize errno */

	if ((((pcp == NULL)
	|| row >= pcp->line_cnt)
	|| col >= pcp->max_cols_cnt)
	|| col >= pcp->lines[row]->cols_cnt
	) {	return	NULL; /* illegal argument */	}

	return pcp->lines[row]->cols[col]; /* the value of CSV field */
}


/* Helper function for `write_csv_columns()'.
 * This function writes 'str' string to 'fp' CSV file.  If '*column_pos'
 * is greater than zero, this writes comma before 'str' string.
 */
static FILE *write_csv_column(FILE			*fp
							, const char	delimit
							, long			*column_pos
							, char			*str
							)
{
	size_t	len = strlen(str);

	errno	= 0; /* initialize errno */

	/* Is current position the head of line in CSV file,
	 * and the string is empty?
	 */
	if ((*column_pos == 0) && len == 0) {
		/* write nothing */
		return	fp; /* normal end */
	}

	/* The cell is the second or later cell? */
	if (*column_pos > 0) {
		/* write a comma */
		if (fputc((int)delimit, fp) != (int)delimit) {
			return	NULL; /* I/O error */
		}
	}

	/* The string isn't empty? */
	if (len > 0) {
		/* write the string */
		if (fwrite(str, 1, len, fp) != len) {
			return	NULL;	/* I/O error */
		}
	}

	return	fp;	/* NORMAL END */
}

/* This API writes the CSV cell data, those are C-strings,
 * to `file_path' CSV file.
 *
 * Variable arguments describes the direction for writing data.
 * o CSV_END means end of cells and directive to close the file.
 * o CSV_CONTINUE means the directives continues to the next invocation.
 *   (the next invocation must have NULL at 'file_path' argument)
 * o CSV_EOL means writing end of record ("\r\n") to the CSV file.
 * o CSV_EMPTY means writes several empty cells.
 *   This directive will be described as...
 * 	`CSV_EMPTY, <number of empty cells>,'
 *   (<number of empty cells> must be zero or positive integer.)
 * o CSV_COLUMN means writes a CSV cell.
 *   This directive will be described as...
 *      `CSV_COLUMN, <number of output characters>, <data of a cell>,'
 *   (<number of output characters> limits the output length.
 *    <data of a cell> points the string.)
 */
FILE *write_csv_columns(const char		*file_path
						, const char	delimit
						, FILE			*fp
						, long			*column_pos
						, ...
						)
{
	va_list	ap; /* cursor of variable argument list */
	size_t	csvstr_sz = 0L, strsz;
	char	*str, *new_csvstr, *csvstr = NULL;
	int		directive, digits, sv_errno, wrote_something = 0;

	errno	= 0; /* initialize errno */

	/* test: arguments are illegal? */
	if (((((((file_path == NULL && fp == NULL)
	|| column_pos == NULL) || *column_pos < 0)
	|| delimit == EOS) || delimit == DQ)
	|| delimit == CR) || delimit == LF
	) {	/* Error: invalid arguments */
		errno = EINVAL; return NULL;	/* Error */
	}

	/* The path of output file is specified? */
	if (file_path != NULL) {
		/* create/truncate the output file */
		if ((fp = fopen(file_path, "w")) == NULL) {
			return	NULL; /* Failed to create file */
		}

		*column_pos	= 0; /* initialize the current position of output */
	}

	/* start parsing the variable arguments... */
	va_start(ap, column_pos);
	do {
		directive	= va_arg(ap, int); /* get the directive */

		/* test: judge the directive */
		switch (directive) {
		case CSV_END: /* end of cells and close the file */
			/* last position of output must be head of record. or,
			 * we yet wrote something, flush the I/O buffer
			 */
			strsz	= strlen(CR_LF_SEQ);
			if (((*column_pos > 0)
				&& fwrite(CR_LF_SEQ, 1, strsz, fp) < strsz)
			|| (((*column_pos > 0) || wrote_something != 0)
				&& fflush(fp) != 0)
			) {	/* failed to write end of record, or, failed to flush
				 *I/O buffer
				 */
				sv_errno = errno; (void)fclose(fp); errno = sv_errno
				;
				fp	= NULL; /* file I/O error */
			}
			else if (fclose(fp) != 0) {
				/* failed to close the file */
				fp	= NULL; /* Occurred I/O error */
			}
			else {	/* re-initialize the current position of the output */
				*column_pos	= 0;
			}
			goto EXIT_LOOP; /* finished the processing! */

		case CSV_CONTINUE: /* continue to the next invocation */
			/* flush the I/O buffer */
			if ((wrote_something != 0) && fflush(fp) != 0) {
				fp	= NULL; /* file I/O error */
			}
			goto EXIT_LOOP; /* finshed the processing! */

		case CSV_EOL: /* write end of record sequence */
			strsz	= strlen(CR_LF_SEQ);
			if (fwrite(CR_LF_SEQ, 1, strsz, fp) < strsz) {
				goto VARARG_ERROR; /* Occurred I/O error */
			}

			/* re-initialize the current position of the output */
			*column_pos = 0; wrote_something = !0;
			break;

		case CSV_EMPTY: /* write several empty cells */
			digits	= va_arg(ap, int); /* get number of empty cells */

			/* test: digits is illegal? */
			if (digits < 0) {
				/* Error: invalid arguments */
				errno	= EINVAL; goto VARARG_ERROR;
			}

			/* iterate until the number... */
			while (digits-- > 0) {
				/* write a empty cell */
				if (write_csv_column(fp, delimit, column_pos, "") == NULL)
				{	goto VARARG_ERROR; /* Occurred I/O error */	}

				/* increment the current position */
				++(*column_pos); wrote_something = !0;
			}
			break;
				
		case CSV_COLUMN: /* write a cell data */
			/* get the limit of output character */
			digits	= va_arg(ap, int);
			/* get the address of the output string */
			str	= va_arg(ap, char *);

			/* test: digits and address of string are illegal? */
			if ((digits < 0) || str == NULL) {
				/* Error: invalid arguments */
				errno = EINVAL; goto VARARG_ERROR;
			}

			/* get size of the CSV formatted string buffer */
			strsz = GET_MAX_SZ_OF_CSV_STR(str);

			/* the allocated buffer is insufficient? */
			if ((csvstr == NULL) || csvstr_sz < strsz) {
				/* allocate the CSV format buffer */
				if ((new_csvstr = (char *)realloc(csvstr, strsz)) == NULL)
				{	/* Error: insufficient memory */
					errno = ENOMEM; goto VARARG_ERROR;
				}
				csvstr	= new_csvstr;
			}

			/* convert data string to CSV format */
			{
				size_t	csv_len = 0L;
				int		do_quoting = 0;

				/* initialize the csv buffer */
				memset(csvstr, (int)'\0', (csvstr_sz = strsz));

				/* convert the data string... */
				while ((digits-- > 0) && *str != '\0') {
					/* the character needs to be quoting? */
					if ((*str == delimit) || *str == LF) {
						do_quoting = 1; /* set quoting flag */
					}

					/* the character is double-quote? */
					if (*str == DQ) {
						/* duplicate the code */
						strcat(csvstr, "\"\""); csv_len += 2; ++str;

						do_quoting = 1; /* set quoting flag */
					}
					else {
						/* copy the character */
						csvstr[csv_len++] = *str++;
					}
				}

				/* test: quoting flag is set? */
				if (do_quoting != 0) {
					/* insert double-quote */
					strsz	= strlen(csvstr);
					for (csvstr[strsz + 1] = '"'; strsz > 0; --strsz) {
						csvstr[strsz]	= csvstr[strsz - 1];
					}
					csvstr[0]	= '"';
				}
			}

			/* write the csv format string */
			if (write_csv_column(fp, delimit, column_pos, csvstr) == NULL)
			{	goto VARARG_ERROR; /* Error: Occurred I/O error */	}

			/* increment the current position of file */
			++(*column_pos); wrote_something = !0;
			
			break;

		default: /* unknown directive */
			errno	= EINVAL; /* illegal arguments */

VARARG_ERROR: /* occurred I/O error */
			/* save the first occurred errno */
			sv_errno = errno;

			/* test: wrote something, yet? */
			if (wrote_something != 0) {
				(void)fflush(fp); /* flush the I/O buffer */
			}

			(void)fclose(fp); /* close the file */

			errno	= sv_errno /* restore the first errno */
			; fp	= NULL	/* Occurred error */
			;
			break;
		}
	} while (fp != NULL);

EXIT_LOOP:
	va_end(ap); /* ...finish parsing the variable arguments */

	/* the csv format buffer was allocated? */
	if (csvstr_sz > 0L) {
		/* release the allocated memory */
		free(csvstr); csvstr = NULL;
		csvstr_sz = 0L;
	}

	return	fp; /* NORMAL END: non-NULL, ERROR: NULL */
}
