/*
 * dsngctl - Control utility for DigSig-ng (digsig-ng.org)
 *
 * key_extract.c - extract MPIs from GPG exported keys
 *
 * Copyright (c) 2013, The DigSig-ng Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Distributed Security Module (DSM)
 *
 * Simple extractor of MPIs for e and n in gpg exported keys (or pubrings
 * with only one key apparently)
 * Exported keys come from gpg --export.
 * Output is meant to be copy pasted into kernel code until better mechanism.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: David Gordon Aug 2003
 * Modifs: Vincent Roy  Sep 2003
 *         Chris Wright Sep 2004
 *         Axelle Apvrille Feb 2005
 */

#include "extract.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DIGSIG_ELF_SIG_SIZE  512 /* this is a redefinition */
#define DIGSIG_PKEY_N_OFFSET   8 /* offset for pkey->n */
#define DIGSIG_MPI_MAX_SIZE  512 /* maximum MPI size in BYTES */

int check_pubkey(int pkey_file)
{
	unsigned char c;
	unsigned int header_len;
	const int RSA_ENCRYPT_OR_SIGN = 1;
	const int RSA_SIGN = 3;
	const int CREATION_TIME_LENGTH = 4;

	/* reading packet tag byte: a public key should be : 100110xx */
	read(pkey_file, &c, 1);
	if (!(c & 0x80)) {
		fprintf(stderr, "dsngctl: %s: bad packet tag byte: this is not an OpenPGP message\n", __func__);
		return -1;
	}
	if (c & 0x40) {
		fprintf(stderr, "dsngctl: %s: packet tag: new packet headers are not supported\n", __func__);
		return -1;
	}
	if (!(c & 0x18)) {
		fprintf(stderr, "dsngctl: %s: packet tag: this is not a public key\n", __func__);
		return -1;
	}

	switch (c & 0x03) {
	case 0:
		header_len = 2;
		break;
	case 1:
		header_len = 3;
		break;
	case 2:
		header_len = 5;
		break;
	case 3:
	default:
		fprintf(stderr, "dsngctl: %s: packet tag: indefinite length headers are not supported\n", __func__);
		return -1;
	}

	/* skip the rest of the header */
	/*printf("Header len:%d\n",header_len); */
	header_len--;
	lseek(pkey_file, header_len, SEEK_CUR);

	/* Version 4 public key message formats contain:
	 1 byte for the version
	 4 bytes for key creation time
	 1 byte for public key algorithm id
	 MPI n
	 MPI e
	 */
	read(pkey_file, &c, 1);
	/*printf("Version %d\n",c);*/
	if (c != 4) {
		fprintf(stderr, "dsngctl: %s: unsupported pkey version\n",
			__func__);
		return -1;
	}

	lseek(pkey_file, CREATION_TIME_LENGTH, SEEK_CUR); /* skip packet creation time */
	read(pkey_file, &c, 1);
	if (c != RSA_ENCRYPT_OR_SIGN && c != RSA_SIGN) {
		fprintf(stderr, "dsngctl: %s: this is not an RSA key, or signatures not allowed\n", __func__);
		return -1;
	}

	return 0; /* OK */
}

int get_mpi(int pkey_file, int module_file, char tag)
{
	unsigned char c;
	unsigned int len;
	unsigned char *key;
	int i;
	int key_offset = 0;

	key = (unsigned char *) malloc(DIGSIG_MPI_MAX_SIZE + 1);
	if (key == NULL) {
		fprintf(stderr, "dsngctl: %s: cannot allocate key buffer\n",
			__func__);
		return -1;
	}

	/* buffers we send to digsig module are prefixed by a character */
	key[key_offset++] = tag;

	/* first two bytes represent MPI's length in BITS */
	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len = c << 8;

	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len |= c;
	len = (len + 7) / 8; /* Bit to Byte conversion */

	/* read the MPI */
	read(pkey_file, &key[key_offset], len);
	key_offset += len;

	/* send MPI to kernel module */
	if (write(module_file, key, key_offset) < 0) {
		fprintf(stderr, "dsngctl: %s: write problem %i: %s\n", __func__,
			errno, strerror(errno));
		return -1;
	}

	printf("MPI: %c (len=%d)\n{ ", tag, len);
	for (i = 0; i < key_offset; i++) {
		printf("0x%02X, ", key[i] & 0xff);
	}
	printf("}\n");

	return 0; /* OK */
}
