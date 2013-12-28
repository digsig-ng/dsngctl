/*
 * dsngctl - Control utility for DigSig-ng (digsig-ng.org)
 *
 * Copyright (c) 2013, The DigSig-ng Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "interface.h"
#include "extract.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int dsng_start(char *pkey_path)
{
	int ret = -1;
	int pkey_file, mod_file;

	pkey_file = open(pkey_path, O_RDONLY);
	if (pkey_file < 0) {
		fprintf(stderr, "dsngctl: %s: unable to open public key\n", __func__);
		goto cleanup_done;
	}

	mod_file = open("/sys/digsig/key", O_WRONLY);
	if (pkey_file < 0) {
		fprintf(stderr, "dsngctl: %s: unable to open module char device\n",
			__func__);
		goto cleanup_pkey;
	}

	if (check_pubkey(pkey_file) != 0) {
		fprintf(stderr, "dsngctl: %s: public key invalid\n", __func__);
		goto cleanup_mod;
	}

	if (get_mpi(pkey_file, mod_file, 'n') != 0) {
		fprintf(stderr, "dsngctl: %s: get_mpi(..., ..., 'n') failed\n",
			__func__);
		goto cleanup_mod;
	}

	if (get_mpi(pkey_file, mod_file, 'e') != 0) {
		fprintf(stderr, "dsngctl: %s: get_mpi(..., ..., 'e') failed\n",
			__func__);
		goto cleanup_mod;
	}

	ret = 0;

cleanup_mod:
	close(mod_file);
cleanup_pkey:
	close(pkey_file);
cleanup_done:
	return ret;
}
