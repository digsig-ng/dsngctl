/*
 * dsngctl - Control utility for DigSig-ng (digsig-ng.org)
 *
 * main.c - command line utility
 *
 * Copyright (c) 2013, The DigSig-ng Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "interface.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Checks whether the current process is running as root.
 *
 * @return 1 if root, 0 otherwise.
 */
static int check_root()
{
	return getuid() == 0;
}

/**
 * Prints the usage line to standard output.
 */
static void print_usage(char *name)
{
	printf("usage: %s [start|status|help]\n", name);
}

/**
 * Prints the help documentation to standard output.
 */
static void print_help(char *name)
{
	print_usage(name);
	printf("\n");
	printf("    %s start [pkey]\n", name);
	printf("        Loads a private key to the kernel module.\n");
	printf("        You can export a key with `gpg --export > pkey`\n");
	printf("\n");
	printf("    %s status\n", name);
	printf("        Determines the current status of the module, whether it is loaded and running.\n");
	printf("\n");
	printf("    %s help\n", name);
	printf("        Prints this message to standard output.\n");
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (argc >= 2 && (strcmp(argv[1], "help") == 0)) {
		print_help(argv[0]);
		return 0;
	}

	if (argc >= 2 && (strcmp(argv[1], "start") == 0)) {
		if (argc < 3) {
			fprintf(stderr, "dsngctl: invalid number of parameters for start command\n");
			return 1;
		}

		if (!check_root()) {
			fprintf(stderr, "dsngctl: start command must be run as root\n");
			return 1;
		}

		ret = dsng_start(argv[2]);
	}

	if (argc >= 2 && (strcmp(argv[1], "status") == 0)) {
		if (!check_root()) {
			fprintf(stderr, "dsngctl: status command must be run as root\n");
			return 1;
		}

		printf("dsngctl: digsig-ng status\n\t"
			"module loaded:\t\t%s\n\t"
			"module initialized:\t%s\n",
			digsig_is_loaded() ? "loaded" : "not loaded",
			digsig_is_initialized() ? "initialized" : "not initialized");

		return 0;
	}

	return ret;
}
