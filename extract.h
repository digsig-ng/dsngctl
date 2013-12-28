/*
 * dsngctl - Control utility for DigSig-ng (digsig-ng.org)
 *
 * key_extract.h - extract MPIs from GPG exported keys
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

#ifndef DSNGCTL_KEY_EXTRACT_H
#define DSNGCTL_KEY_EXTRACT_H

/**
 * Checks public key file format. This should be an OpenPGP message containing
 * an RSA public key.
 *
 * TODO: check all errors
 *
 * @param pkey_file the public key file descriptor (file must be readable)
 *
 * @return -1 if error
 * 0 if successful, the file pointer has moved just at the beginning of the first MPI.
 */
int check_pubkey(int pkey_file);

/**
 * Retrieves an MPI and sends it to DigSig kernel module.
 * The file must be set at the beginning of the MPI.
 *
 * TODO: test for read/write errors.
 *
 * @param pkey_file the public key file. Must be readable and pointing on the
 *                  beginning of an MPI.
 *
 * @param module_file the sys file to communicate with the DigSig kernel
 *                    module. Must be open and writable.
 *
 * @param tag a character identifying what we read. This character is prefixed
 *            to the MPI and sent to the kernel module.
 *
 * @return 0 if successful, and then the file points just after the MPI.
 */
int get_mpi(int pkey_file, int module_file, char tag);

#endif /* DSNGCTL_KEY_EXTRACT_H */
