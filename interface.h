/*
 * dsngctl - Control utility for DigSig-ng (digsig-ng.org)
 *
 * interface.h - functions for interfacing with the kernel module
 *
 * Copyright (c) 2013-2014, The DigSig-ng Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef DSNG_INTERFACE_H
#define DSNG_INTERFACE_H

/**
 * Reads a public key from the provided path and loads it into the kernel
 * module.
 *
 * @param pkey_path Path to public key.
 *
 * @returns 0 upon success, or negative integer representing error code.
 */
int dsng_start(char *pkey_path);

/**
 * Determines whether the kernel module has been loaded by attempting to stat
 * a module sysfs file.
 *
 * @returns 1 if the module has been loaded, 0 otherwise.
 */
int digsig_is_loaded();

/**
 * Determines whether the kernel module is initialized by reading the module
 * status from /sys/digsig/status.
 *
 * @returns 1 if the module has been initialized, 0 otherwise.
 */
int digsig_is_initialized();

#endif /* DSNG_INTERFACE_H */
