/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#ifndef NODE_H
#define NODE_H

#define SEARCH_RESULT_MAX 8

struct search {
    unsigned char id[20];
    uint16_t tid;
    struct timeval next_query;
    int search_type;
    struct search_node *queue;
    size_t node_count;
    search_complete_t callback;
    void *opaque;
    struct search *next;
    struct search **pprev;
};

struct bucket_entry {
    unsigned char id[20];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct timeval last_seen;
    struct timeval next_ping;
    int pinged;
};

#define BUCKET_ENTRY_MAX 8

struct bucket {
    unsigned char first[20];
    struct bucket_entry nodes[BUCKET_ENTRY_MAX];
    size_t cnt;
    struct timeval refresh_time;
    struct bucket *next;
    struct search *refresh;
};

struct peer {
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct timeval expire_time;
    struct peer *next;
};

struct peer_list {
    unsigned char info_hash[20];
    struct peer *peers;
    struct peer_list *next;
};

struct put_item {
    unsigned char hash[20];
    unsigned char k[32];
    int seq;
    unsigned char sig[64];
    struct bvalue *v;
    struct timeval expire_time;
    struct put_item *next;
};

static const struct timeval bucket_node_timeout = {
    .tv_sec = 15 * 60,
    .tv_usec = 0
};
static const struct timeval bucket_refresh_timeout = {
    .tv_sec = 15 * 60,
    .tv_usec = 0
};
static const struct timeval search_iteration_timeout = {
    .tv_sec = 1,
    .tv_usec = 0
};
static const struct timeval peer_timeout = {
    .tv_sec = 2 * 60 * 60,
    .tv_usec = 0
};
static const struct timeval search_query_timeout = {
    .tv_sec = 10,
    .tv_usec = 0,
};
static const struct timeval ping_timeout = {
    .tv_sec = 10,
    .tv_usec = 0,
};
static const struct timeval put_timeout = {
    .tv_sec = 2 * 60 * 60,
    .tv_usec = 0,
};

#define SAVE_FILE_VERSION 2

#endif /* NODE_H */
