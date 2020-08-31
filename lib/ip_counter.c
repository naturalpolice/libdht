/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stdlib.h>
#include <string.h>

#include <dht/node.h>

#include "time.h"

void ip_counter_reset(struct ip_counter *c)
{
    struct ip_counter_entry *e = c->entries;

    while (e) {
        struct ip_counter_entry *n = e->next;

        free(e);
        e = n;
    }
    c->entries = NULL;

    c->total = 0;
    gettimeofday(&c->heat_start, NULL);
}

void ip_counter_init(struct ip_counter *c)
{
    c->total = 0;
    c->entries = NULL;
    gettimeofday(&c->heat_start, NULL);
}

int ip_counter_update(struct ip_counter *c, const unsigned char *ip,
                      size_t len)
{
    struct ip_counter_entry **e = &c->entries;
    struct timeval tv, now;

    while (*e && ((*e)->len != len || memcmp((*e)->ip, ip, len)))
        e = &(*e)->next;

    if (*e)
        (*e)->count++;
    else {
        *e = malloc(sizeof(struct ip_counter_entry));
        if (!(*e))
            return -1;
        (*e)->count = 1;
        memcpy(&(*e)->ip, ip, len);
        (*e)->len = len;
        (*e)->next = NULL;
    }

    c->total++;

    gettimeofday(&now, NULL);
    tv.tv_sec = 10 * 60;
    tv.tv_usec = 0;
    timeradd(&tv, &c->heat_start, &tv);

    if (c->total >= 120 || timercmp(&tv, &now, <=))
        return 1;

    return 0;
}

int ip_counter_current(struct ip_counter *c, unsigned char ip[18])
{
    struct ip_counter_entry *e = c->entries;
    struct ip_counter_entry *max = NULL;

    while (e) {
        if (!max || max->count < e->count)
            max = e;
        e = e->next;
    }

    if (!max)
        return -1;

    memcpy(ip, max->ip, max->len);
    return max->len;
}
