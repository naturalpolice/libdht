/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stddef.h>
#include <stdio.h>
#include <ctype.h>

void hexdump(const unsigned char *buf, size_t len, unsigned int indent,
             int (*print)(const char *fmt, ...))
{
    size_t j, i = 0;

    if (!print)
        print = printf;

    while (i < len) {
        for (j = 0; j < indent; j++)
            print("  ");
        print("%02x", buf[i]);
        for (j = 1; j < 16 && i + j < len; j++)
            print(" %02x", buf[i + j]);
        for (; j < 16; j++)
            print("   ");
        print("  ");

        for (j = 0; j < 16 && i + j < len; j++) {
            if (isprint(buf[i + j]))
                print("%c", buf[i + j]);
            else
                print(".");
        }
        i += j;
        print("\n");
    }
}
