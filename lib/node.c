/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <netdb.h> /* getaddrinfo */
#endif
#include <stdarg.h>

#include <dht/utils.h>
#include <dht/node.h>

#include "time.h"
#include "ed25519/ed25519.h"
#include "hmac.h"
#include "random.h"
#include "ip_counter.h"
#include "node.h"

static
#if defined(__GNUC__)
__attribute__ ((format (printf, 1, 2)))
#endif
int debug_printf(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vfprintf(stderr, format, ap);
    va_end(ap);

    return ret;
}

#ifdef DHT_DEBUG
#define TRACE(x) debug_printf x
#else
#define TRACE(x) do { if (0) debug_printf x; } while (0)
#endif

static void send_query(struct dht_node *n, const char *method, uint16_t tid,
                       struct bvalue *arguments,
                       const struct sockaddr *dest, socklen_t addrlen)
{
    unsigned char buf[2048];
    struct bvalue *query;
    struct bvalue *v;
    int rc;

    query = bvalue_new_dict();
    v = bvalue_new_string((unsigned char *)&tid, sizeof(tid));
    bvalue_dict_set(query, "t", v);

    v = bvalue_new_string((unsigned char *)"q", 1);
    bvalue_dict_set(query, "y", v);

    v = bvalue_new_string((unsigned char *)method, strlen(method));
    bvalue_dict_set(query, "q", v);

    if (!arguments)
        arguments = bvalue_new_dict();
    v = bvalue_new_string(n->id, 20);
    bvalue_dict_set(arguments, "id", v);
    bvalue_dict_set(query, "a", arguments);

    rc = bencode_buf(query, buf, sizeof(buf));
    if (rc < 0) {
        TRACE(("bencoding failed\n"));
        bvalue_free(query);
        return;
    }

    n->output(buf, rc, dest, addrlen, n->opaque);

    bvalue_free(query);
}

int compact_to_sockaddr(const struct bvalue *v, struct sockaddr *addr,
                        socklen_t *addrlen)
{
    size_t l;
    const unsigned char *p;

    if (!(p = bvalue_string(v, &l)))
        return -1;

    switch (l) {
    case 6:
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;

            sin->sin_family = AF_INET;
            memcpy(&sin->sin_addr, p, 4);
            memcpy(&sin->sin_port, p + 4, 2);
            *addrlen = sizeof(*sin);
            break;
        }
    case 18:
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

            sin6->sin6_family = AF_INET6;
            memcpy(&sin6->sin6_addr, p, 16);
            memcpy(&sin6->sin6_port, p + 16, 2);
            *addrlen = sizeof(*sin6);
            break;
        }
    default:
        return -1;
    }

    return 0;
}

static struct bvalue *bvalue_new_compact(const struct sockaddr *addr,
                                         socklen_t addrlen)
{
    unsigned char buf[18];

    (void)addrlen;

    switch (addr->sa_family) {
    case AF_INET:
        {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

            memcpy(buf, &sin->sin_addr, 4);
            memcpy(buf + 4, &sin->sin_port, 2);
        }
        return bvalue_new_string(buf, 6);
    case AF_INET6:
        {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

            memcpy(buf, &sin6->sin6_addr, 16);
            memcpy(buf + 16, &sin6->sin6_port, 2);
        }
        return bvalue_new_string(buf, 18);
    default:
        break;
    }

    return NULL;
}

#ifndef TESTING
static void send_response(struct dht_node *n,
                          const unsigned char *tid, size_t tid_len,
                          struct bvalue *ret,
                          const struct sockaddr *dest, socklen_t addrlen)
{
    unsigned char buf[2048];
    struct bvalue *response;
    struct bvalue *v;
    int rc;

    response = bvalue_new_dict();
    v = bvalue_new_string(tid, tid_len);
    bvalue_dict_set(response, "t", v);

    v = bvalue_new_string((unsigned char *)"r", 1);
    bvalue_dict_set(response, "y", v);

    v = bvalue_new_compact(dest, addrlen);
    if (v)
        bvalue_dict_set(response, "ip", v);

    if (!ret)
        ret = bvalue_new_dict();
    v = bvalue_new_string(n->id, 20);
    bvalue_dict_set(ret, "id", v);
    bvalue_dict_set(response, "r", ret);

    rc = bencode_buf(response, buf, sizeof(buf));
    if (rc < 0) {
        TRACE(("bencoding failed\n"));
        bvalue_free(response);
        return;
    }

    n->output(buf, rc, dest, addrlen, n->opaque);

    bvalue_free(response);
}

static void send_error(struct dht_node *n,
                       const unsigned char *tid, size_t tid_len,
                       int error_code, const char *error_msg,
                       const struct sockaddr *dest, socklen_t addrlen)
{
    unsigned char buf[2048];
    struct bvalue *response;
    struct bvalue *error;
    struct bvalue *v;
    int rc;

    response = bvalue_new_dict();

    if (tid) {
        v = bvalue_new_string(tid, tid_len);
        bvalue_dict_set(response, "t", v);
    }

    v = bvalue_new_string((unsigned char *)"e", 1);
    bvalue_dict_set(response, "y", v);

    v = bvalue_new_compact(dest, addrlen);
    bvalue_dict_set(response, "ip", v);

    error = bvalue_new_list();
    v = bvalue_new_integer(error_code);
    bvalue_list_append(error, v);
    v = bvalue_new_string((unsigned char *)error_msg, strlen(error_msg));
    bvalue_list_append(error, v);
    bvalue_dict_set(response, "e", error);

    rc = bencode_buf(response, buf, sizeof(buf));
    if (rc < 0) {
        TRACE(("bencoding failed\n"));
        bvalue_free(response);
        return;
    }

    n->output(buf, rc, dest, addrlen, n->opaque);

    bvalue_free(response);
}
#endif

static void distance(const unsigned char id1[20], const unsigned char id2[20],
                     unsigned char ret[20])
{
    size_t i;

    for (i = 0; i < 20; i++)
        ret[i] = id1[i] ^ id2[i];
}

static int get_closest(struct dht_node *n, const unsigned char *id,
                       struct bucket_entry *nodes,
                       size_t sz)
{
    size_t i, j, k, cnt = 0;
    struct bucket *b = n->buckets;
    unsigned char *distances;

    distances = malloc(sz * 20);
    if (!distances)
        return -1;

    while (b) {
        for (i = 0; i < b->cnt; i++) {
            unsigned char d[20];

            distance(id, b->nodes[i].id, d);

            for (j = 0; j < cnt; j++) {
                if (memcmp(d, distances + j * 20, 20) < 0)
                    break;
            }

            if (j < sz) {
                for (k = cnt < sz ? cnt : sz - 1; k > j; k--) {
                    memcpy(distances + k * 20, distances + (k - 1) * 20, 20);
                    nodes[k] = nodes[k - 1];
                }
                memcpy(distances + j * 20, d, 20);
                nodes[j] = b->nodes[i];
                if (cnt < sz)
                    cnt++;
            }
        }

        b = b->next;
    }

    free(distances);

    return cnt;
}

static void add_search_node(struct search *s, const unsigned char *id,
                            const struct sockaddr *addr, socklen_t addrlen)
{
    struct search_node *new, **pn = &s->queue;
    unsigned char d1[20];

    distance(id, s->id, d1);

    while (*pn) {
        unsigned char d2[20];
        int r;

        distance((*pn)->id, s->id, d2);
        r = memcmp(d1, d2, 20);
        if (r == 0)
            return; /* We already have this one, skip */
        else if (r < 0)
            break;

        pn = &(*pn)->next;
    }

    new = malloc(sizeof(struct search_node));
    if (!new)
        return;

    memcpy(new->id, id, 20);
    memcpy(&new->addr, addr, addrlen);
    new->addrlen = addrlen;
    new->token = NULL;
    new->token_len = 0;
    new->peers = NULL;
    new->peer_count = 0;
    new->v = NULL;
    new->seq = -1;
    timerclear(&new->reply_time);
    timerclear(&new->next_query);
    new->queried = 0;
    new->error = 0;

    new->next = *pn;
    *pn = new;

    s->node_count++;
}

static void search_node_free(struct search_node *sn)
{
    if (sn->token)
        free(sn->token);
    if (sn->peers)
        free(sn->peers);
    if (sn->v)
        bvalue_free(sn->v);
    free(sn);
}

static void search_complete(struct dht_node *n, struct search *s)
{
    struct search_node *sn = s->queue;

    TRACE(("Search %s complete\n", hex(s->id)));

    if (s->callback)
        s->callback(n, sn, s->opaque);

    sn = s->queue;
    while (sn) {
        struct search_node *next = sn->next;

        search_node_free(sn);
        sn = next;
    }

    if (s->next)
        s->next->pprev = s->pprev;
    else
        n->searches.tail = s->pprev;
    *s->pprev = s->next;

    free(s);
}

static struct bucket_entry *get_random_node(struct dht_node *n)
{
    struct bucket *b = n->buckets;
    uint32_t r, count = 0;

    while (b) {
        count += b->cnt;
        b = b->next;
    }
    if (!count)
        return NULL;
    r = random_value_uniform(count);
    b = n->buckets;
    while (b) {
        if (r < b->cnt)
            break;
        r -= b->cnt;
        b = b->next;
    }

    return &b->nodes[r];
}

static void search_progress(struct dht_node *n, struct search *s,
                            const struct timeval *now)
{
    struct search_node *sn, **sp;
    struct bvalue *args, *v;
    int nqueries = 0;
    int nreplied = 0;

    if (timercmp(&s->next_query, now, >))
        return;

    sp = &s->queue;
    while ((sn = *sp)) {
        /* The node has replied */
        if (timerisset(&sn->reply_time)) {
            /*
             * The search terminates when enough nodes close to the target have
             * replied and we have not heard of other nodes any closer that we
             * can query.
             */
            if (++nreplied >= SEARCH_RESULT_MAX && !nqueries) {
                search_complete(n, s);
                return;
            }
            goto cont;
        }

        /* Node has errored, ignore it */
        if (sn->error)
            goto cont;

        /* Only query the same node once every 10 seconds */
        if (timerisset(&sn->next_query) &&
            timercmp(&sn->next_query, now, >))
            goto cont;

        if (sn->queried >= 2) {
            /* This node failed to respond to us twice, evict it from search */
            *sp = sn->next;
            free(sn);
            continue;
        }

        args = bvalue_new_dict();
        v = bvalue_new_string(s->id, 20);
        switch (s->search_type) {
        case FIND_NODE:
            bvalue_dict_set(args, "target", v);
            send_query(n, "find_node", s->tid, args,
                       (struct sockaddr *)&sn->addr, sn->addrlen);
            break;
        case GET_PEERS:
            bvalue_dict_set(args, "info_hash", v);
            send_query(n, "get_peers", s->tid, args,
                       (struct sockaddr *)&sn->addr, sn->addrlen);
            break;
        case GET:
            bvalue_dict_set(args, "target", v);
            send_query(n, "get", s->tid, args,
                       (struct sockaddr *)&sn->addr, sn->addrlen);
            break;
        default:
            break;
        }

        sn->queried++;
        timeradd(now, &search_query_timeout, &sn->next_query);

        /* Only query the 8 closest nodes we heard about */
        if (++nqueries >= 8)
            break;
    cont:
        sp = &sn->next;
    }

    TRACE(("search %s: replied=%d, queried=%d\n", hex(s->id),
           nreplied, nqueries));

    if (nqueries == 0) {
        struct bucket_entry *e = get_random_node(n);

        /*
         * Pick a random node from the routing table to query, in case
         * the search has stalled.
         */
        if (e)
            add_search_node(s, e->id, (struct sockaddr *)&e->addr, e->addrlen);
    }

    timeradd(now, &search_iteration_timeout, &s->next_query);
}

int dht_node_search(struct dht_node *n, const unsigned char id[20],
                    int search_type,
                    search_complete_t callback, void *opaque,
                    dht_search_t *handle)
{
    struct search *s = malloc(sizeof(struct search));
    struct timeval now;
    int i, cnt;
    struct bucket_entry closest[8];

    if (!s)
      return -1;

    gettimeofday(&now, NULL);

    TRACE(("Starting search for %s\n", hex(id)));

    memcpy(s->id, id, 20);
    s->next_query = now;
    s->tid = n->tid++;
    s->search_type = search_type;
    s->callback = callback;
    s->opaque = opaque;
    s->queue = NULL;
    s->node_count = 0;

    s->next = NULL;
    s->pprev = n->searches.tail;
    *n->searches.tail = s;
    n->searches.tail = &s->next;

    cnt = get_closest(n, s->id, closest, 8);
    for (i = 0; i < cnt; i++)
        add_search_node(s, closest[i].id, (struct sockaddr *)&closest[i].addr,
                        closest[i].addrlen);
    search_progress(n, s, &now);

    if (handle)
        *handle = s;

    return 0;
}

void dht_node_cancel(struct dht_node *n, dht_search_t handle)
{
    struct search *s = handle;
    struct search_node *sn = s->queue;

    /* Free search queue */
    sn = s->queue;
    while (sn) {
        struct search_node *next = sn->next;

        search_node_free(sn);
        sn = next;
    }
    s->queue = NULL;

    search_complete(n, s);
}

void dht_node_dump_buckets(struct dht_node *n)
{
    struct bucket *b = n->buckets;

    fprintf(stdout, "buckets:\n");
    while (b) {
        size_t i;

        fprintf(stdout, "  - %s", hex(b->first));
        if (b->next)
            fprintf(stdout, "-%s:\n", hex(b->next->first));
        else
            fprintf(stdout, ":\n");

        for (i = 0; i < b->cnt; i++)
            fprintf(stdout, "    * %s %s\n", hex(b->nodes[i].id),
                    sockaddr_fmt((struct sockaddr *)&b->nodes[i].addr,
                                 b->nodes[i].addrlen));

        b = b->next;
    }
}

uint32_t crc32c(const unsigned char *data, size_t len);

static uint32_t compute_id_prefix(int family, unsigned char *ip, int r)
{
    uint32_t ret = 0;
    unsigned char buf[8];

    switch (family) {
    case AF_INET:
        buf[0] = (ip[0] & 0x03) | r << 5;
        buf[1] = ip[1] & 0x0f;
        buf[2] = ip[2] & 0x3f;
        buf[3] = ip[3];
        ret = crc32c(buf, 4);
        break;
    case AF_INET6:
        buf[0] = (ip[0] & 0x01) | r << 5;
        buf[1] = ip[1] & 0x03;
        buf[2] = ip[2] & 0x07;
        buf[3] = ip[3] & 0x0f;
        buf[4] = ip[4] & 0x1f;
        buf[5] = ip[5] & 0x3f;
        buf[6] = ip[6] & 0x7f;
        buf[7] = ip[7];
        ret = crc32c(buf, 8);
        break;
    default: break;
    }

    return ret;
}

static int is_prefix_valid(const unsigned char *id, const struct sockaddr *addr,
                           socklen_t addrlen)
{
    uint32_t prefix;

    if (addrlen < sizeof(struct sockaddr))
        return 0;

    switch (addr->sa_family) {
    case AF_INET:
        {
            struct in_addr *in_addr = &((struct sockaddr_in *)addr)->sin_addr;

            /*
             * Any peer on a local network address is exempt from this node ID
             * verification. This includes the following IP blocks:
             *
             * 10.0.0.0/8: reserved for local networks
             * 172.16.0.0/12: reserved for local networks
             * 192.168.0.0/16 reserved for local networks
             * 169.254.0.0/16 reserved for self-assigned IPs
             * 127.0.0.0/8 reserved for loopback
             *
             */
            if (((in_addr->s_addr & 0x000000ff) == 0x0000000A) ||
                ((in_addr->s_addr & 0x0000f0ff) == 0x000010AC) ||
                ((in_addr->s_addr & 0x0000ffff) == 0x0000A8C0) ||
                ((in_addr->s_addr & 0x0000ffff) == 0x0000FEA9) ||
                ((in_addr->s_addr & 0x000000ff) == 0x0000007F))
                return 1;

            prefix = compute_id_prefix(AF_INET, (unsigned char *)in_addr,
                                       id[19] & 0x7);
        }
        break;
    case AF_INET6:
        prefix = compute_id_prefix(AF_INET6,
                (unsigned char *)&((struct sockaddr_in6 *)addr)->sin6_addr,
                id[19] & 0x7);
        break;
    default:
        return 0;
    }

    return ((prefix >> 24) == id[0]) &&
           (((prefix >> 16) & 0xff) == id[1]) &&
           (((prefix >> 8) & 0xf8) == (id[2] & 0xf8));
}

static void bootstrap_done(struct dht_node *n,
                           const struct search_node *nodes,
                           void *opaque);

static void update_prefix(struct dht_node *n, int notify)
{
    uint32_t prefix;
    unsigned char new_id[20];
    size_t len;
    unsigned char current_ip[18];
    struct bucket *b;

    /* Do not change node ID while we're still in the bootstrap process */
    if (n->bootstrap)
        return;

    len = ip_counter_current(&n->ip_counter, current_ip);
    switch (len) {
    case 6:
        prefix = compute_id_prefix(AF_INET, current_ip, n->id[19] & 0x7);
        break;
    case 18:
        prefix = compute_id_prefix(AF_INET6, current_ip, n->id[19] & 0x7);
        break;
    default:
        return;
    }

    memcpy(new_id, n->id, 20);
    new_id[0] = prefix >> 24;
    new_id[1] = (prefix >> 16) & 0xff;
    new_id[2] = ((prefix >> 8) & 0xf8) | (new_id[2] & 0x7);

    ip_counter_reset(&n->ip_counter);

    if (!memcmp(new_id, n->id, 20))
        return;

    TRACE(("external IP address changed: %s, new node ID: %s\n",
           compactaddr_fmt(current_ip, len), hex(new_id)));

    memcpy(n->id, new_id, 20);

    /* Start search to fill up new routing table */
    dht_node_search(n, new_id, FIND_NODE, bootstrap_done, NULL, &n->bootstrap);

    /* Clear bucket list */
    b = n->buckets;
    while (b->next) {
        struct bucket *next = b->next;

        free(b);
        b = next;
    }
    memset(b->first, 0x0, 20);
    b->cnt = 0;
    gettimeofday(&b->refresh_time, NULL);
    timeradd(&b->refresh_time, &bucket_refresh_timeout, &b->refresh_time);
    n->buckets = b;

    if (notify && n->bootstrap_cb)
        n->bootstrap_cb(0, n->bootstrap_priv);
}

static void bootstrap_done(struct dht_node *n,
                           const struct search_node *nodes,
                           void *opaque)
{
    (void)opaque;
    (void)nodes;

    TRACE(("Bootstrap done\n"));
    n->bootstrap = NULL;

    update_prefix(n, 0);

    /*
     * Only consider that bootstrap is finished if update_prefix does not
     * restart the bootstrap search
     */
    if (!n->bootstrap && n->bootstrap_cb)
        n->bootstrap_cb(1, n->bootstrap_priv);
}

int dht_node_init(struct dht_node *n, const unsigned char *id,
                  node_output_t output, void *opaque)
{
    struct bucket *b;
    struct timeval now;

    gettimeofday(&now, NULL);

    if (id)
        memcpy(n->id, id, 20);
    else
        gen_random_bytes(n->id, 20);
    n->output = output;
    n->opaque = opaque;
    n->tid = 0;
    n->searches.first = NULL;
    n->searches.tail = &n->searches.first;
    ip_counter_init(&n->ip_counter);
    gen_random_bytes(n->secret, sizeof(n->secret));
    n->peer_storage = NULL;
    n->put_storage = NULL;

    b = malloc(sizeof(struct bucket));
    if (!b)
        return -1;
    memset(b->first, 0x0, 20);
    b->cnt = 0;
    timeradd(&now, &bucket_refresh_timeout, &b->refresh_time);
    b->next = NULL;
    b->refresh = NULL;

    n->buckets = b;
    n->bootstrap = NULL;
    n->bootstrap_cb = NULL;
    n->bootstrap_priv = NULL;

    return 0;
}

static const struct {
    const char *hostname;
    int port;
} bootstrap_hosts[] = {
    { "dht.transmissionbt.com", 6881 },
    { "router.utorrent.com", 6881 },
    { "router.bittorrent.com", 6881 },
};

int dht_node_start(struct dht_node *n)
{
    TRACE(("Starting node %s\n", hex(n->id)));

    /* Routing table is empty, ping bootstrap nodes */
    if (n->buckets->next == NULL && n->buckets->cnt == 0) {
        struct addrinfo hints;
        size_t i;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;

        for (i = 0; i < sizeof(bootstrap_hosts) / sizeof(bootstrap_hosts[0]);
             i++) {
            struct addrinfo *ai, *p;
            const char *hostname = bootstrap_hosts[i].hostname;
            int port = bootstrap_hosts[i].port;
            int rc = getaddrinfo(hostname, NULL, &hints, &ai);

            if (rc) {
                TRACE(("getaddrinfo %s: %s\n", hostname, gai_strerror(rc)));
                continue;
            }

            for (p = ai; p; p = p->ai_next) {
                switch (p->ai_family) {
                case AF_INET:
                    ((struct sockaddr_in *)p->ai_addr)->sin_port = htons(port);
                    break;
                case AF_INET6:
                    ((struct sockaddr_in6 *)p->ai_addr)->sin6_port = htons(port);
                    break;
                default:
                    continue;
                }

                TRACE(("Pinging %s...\n",
                       p->ai_canonname ? p->ai_canonname : hostname));
                dht_node_ping(n, p->ai_addr, p->ai_addrlen);
            }

            freeaddrinfo(ai);
        }
    }

    dht_node_search(n, n->id, FIND_NODE, bootstrap_done, NULL,
                    &n->bootstrap);

    return 0;
}

static struct bucket *get_bucket(struct dht_node *n, const unsigned char *id)
{
    struct bucket *b = n->buckets;

    while (b->next && memcmp(id, b->next->first, 20) >= 0)
        b = b->next;

    return b;
}

static struct bucket_entry *get_bucket_entry(struct dht_node *n,
                                             const unsigned char *id)
{
    struct bucket *b = get_bucket(n, id);
    size_t i;

    for (i = 0; i < b->cnt; i++) {
        if (!memcmp(b->nodes[i].id, id, 20))
            return &b->nodes[i];
    }

    return NULL;
}

static int lowbit(const unsigned char *id)
{
    int i, j;
    for(i = 19; i >= 0; i--)
        if(id[i] != 0)
            break;

    if(i < 0)
        return -1;

    for(j = 7; j >= 0; j--)
        if((id[i] & (0x80 >> j)) != 0)
            break;

    return 8 * i + j;
}

static int bucket_middle(struct bucket *b, unsigned char *id)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = ((bit1 > bit2) ? bit1 : bit2) + 1;

    if(bit >= 160)
        return -1;

    memcpy(id, b->first, 20);
    id[bit / 8] |= (0x80 >> (bit % 8));

    return 0;
}

static void bucket_random(struct bucket *b, unsigned char *id)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = ((bit1 > bit2) ? bit1 : bit2) + 1;
    int i;
    unsigned char r[20];

    gen_random_bytes(r, 20);

    if(bit >= 160) {
        memcpy(id, b->first, 20);
        return;
    }

    memcpy(id, b->first, bit / 8);
    id[bit / 8] = b->first[bit / 8] & (0xFF00 >> (bit % 8));
    id[bit / 8] |= r[bit / 8] & 0xFF >> (bit % 8);
    for(i = bit / 8 + 1; i < 20; i++)
        id[i] = r[i];
}

static void bucket_gc(struct dht_node *n, struct bucket *b,
                      const struct timeval *now)
{
    size_t i;
    struct bucket_entry *oldest = NULL;

    /*
     * If bucket is full, remove one bad node (if any) and
     * ping the least recently seen questionable node (if any)
     */

    if (b->cnt < BUCKET_ENTRY_MAX)
        return;

    for (i = 0; i < b->cnt; i++) {
        if (b->nodes[i].pinged >= 2 &&
            timercmp(&b->nodes[i].next_ping, now, <=)) {
            TRACE(("removing bad node %s\n", hex(b->nodes[i].id)));
            for (; i < b->cnt - 1; i++)
              b->nodes[i] = b->nodes[i + 1];
            b->cnt = i;
            return;
        }

        if (!oldest || timercmp(&b->nodes[i].last_seen, &oldest->last_seen, <))
            oldest = &b->nodes[i];
    }

    if (timercmp(&oldest->next_ping, now, <=)) {
        TRACE(("pinging old node %s (count=%d)\n", hex(oldest->id),
               oldest->pinged));
        dht_node_ping(n, (struct sockaddr *)&oldest->addr, oldest->addrlen);
        oldest->pinged++;
        timeradd(now, &ping_timeout, &oldest->next_ping);
    }
}

static void add_node(struct dht_node *n, const unsigned char *id,
                     const struct sockaddr *src, socklen_t addrlen)
{
    struct bucket *b = get_bucket(n, id);
    size_t i;
    struct timeval now;

    gettimeofday(&now, NULL);

    if (!memcmp(n->id, id, 20))
        return; /* Trying to add ourselves in the routing table */

    i = 0;
    while (i < b->cnt && memcmp(id, b->nodes[i].id, 20) > 0)
        i++;

    if (i < b->cnt && !memcmp(id, b->nodes[i].id, 20)) {
        /* Already in bucket */

        b->nodes[i].pinged = 0;
        b->nodes[i].last_seen = now;
        timeradd(&now, &bucket_node_timeout, &b->nodes[i].next_ping);
        memcpy(&b->nodes[i].addr, src, addrlen);
        b->nodes[i].addrlen = addrlen;
        timeradd(&now, &bucket_refresh_timeout, &b->refresh_time);
        return;
    }

    if (b->cnt < BUCKET_ENTRY_MAX) {
        size_t j;

        TRACE(("Adding node %s\n", hex(id)));

        i = 0;
        while (i < b->cnt && memcmp(id, b->nodes[i].id, 20) > 0)
            i++;
        for (j = b->cnt; j > i; j--)
            b->nodes[j] = b->nodes[j - 1];
        memcpy(b->nodes[i].id, id, 20);
        memcpy(&b->nodes[i].addr, src, addrlen);
        b->nodes[i].addrlen = addrlen;
        b->nodes[i].last_seen = now;
        timeradd(&now, &bucket_node_timeout, &b->nodes[i].next_ping);
        b->nodes[i].pinged = 0;
        timeradd(&now, &bucket_refresh_timeout, &b->refresh_time);
        b->cnt++;
    } else if (memcmp(n->id, b->first, 20) >= 0 &&
               (!b->next || memcmp(n->id, b->next->first, 20) < 0)) {
        /* Split */
        struct bucket *new = malloc(sizeof(struct bucket));

        if (!new || bucket_middle(b, new->first))
            return;
        new->next = b->next;
        new->cnt = 0;
        new->refresh = NULL;
        new->refresh_time = b->refresh_time;

        b->next = new;

        i = 0;
        while (i < BUCKET_ENTRY_MAX &&
               memcmp(b->nodes[i].id, new->first, 20) < 0)
            i++;
        b->cnt = i;
        while (i < BUCKET_ENTRY_MAX)
            new->nodes[new->cnt++] = b->nodes[i++];

        add_node(n, id, src, addrlen);
    }
}

static struct search *get_search(struct dht_node *n, uint16_t tid)
{
    struct search *s = n->searches.first;

    while (s) {
        if (s->tid == tid)
           return s;
        s = s->next;
    }

    return NULL;
}

static void add_compact_nodes(struct search *s, const unsigned char *nodes,
                              size_t nodes_len)
{
    const unsigned char *end = nodes + nodes_len;

    while (nodes + 26 <= end) {
        struct sockaddr_in sin;

        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, nodes + 20, 4);
        memcpy(&sin.sin_port, nodes + 24, 2);

        add_search_node(s, nodes, (struct sockaddr *)&sin, sizeof(sin));
        nodes += 26;
    }
}

static void add_compact_nodes6(struct search *s, const unsigned char *nodes6,
                               size_t nodes6_len)
{
    const unsigned char *end = nodes6 + nodes6_len;

    while (nodes6 + 38 <= end) {
        struct sockaddr_in6 sin6;

        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        memcpy(&sin6.sin6_addr, nodes6 + 20, 16);
        memcpy(&sin6.sin6_port, nodes6 + 36, 2);

        add_search_node(s, nodes6, (struct sockaddr *)&sin6, sizeof(sin6));
        nodes6 += 38;
    }
}


static struct search_node *get_search_node(struct search *s,
                                           const unsigned char *id)

{
    struct search_node *sn = s->queue;

    while (sn) {
        if (!memcmp(sn->id, id, 20))
            return sn;
        sn = sn->next;
    }

    return NULL;
}

static void search_node_set_token(struct search_node *sn,
                                  const unsigned char *token,
                                  size_t len)
{
    sn->token = malloc(len);
    if (!sn->token)
        return;

    memcpy(sn->token, token, len);
    sn->token_len = len;
}

static void search_node_set_values(struct search_node *sn,
                                   const struct bvalue *list)
{
    size_t i;
    socklen_t dummy;

    if (list->type != BVALUE_LIST)
        return;

    sn->peers = malloc(list->l.len * sizeof(struct sockaddr_storage));
    if (!sn->peers)
        return;
    sn->peer_count = 0;

    for (i = 0; i < list->l.len; i++) {
        if (compact_to_sockaddr(list->l.array[i],
                                (struct sockaddr *)&sn->peers[sn->peer_count],
                                &dummy))
            continue;
        sn->peer_count++;
    }
}

static void search_node_set_v(struct search_node *sn, const struct bvalue *v)
{
    unsigned char flattened[1000];
    int rc;

    rc = bencode_buf(v, flattened, sizeof(flattened));
    if (rc < 0)
        return;

    /* Make copy of v */
    sn->v = bdecode_buf(flattened, rc);
}

static void handle_response(struct dht_node *n, struct bvalue *dict,
                            const struct sockaddr *src, socklen_t addrlen)
{
    const struct bvalue *v, *r;
    const void *p;
    size_t l;
    uint16_t tid;
    const unsigned char *id;
    struct search *s;

    v = bvalue_dict_get(dict, "t");
    if (!v) {
        TRACE(("'t' key missing\n"));
        return;
    }
    p = bvalue_string(v, &l);
    if (!p || l != sizeof(tid)) {
        TRACE(("invalid 't' key\n"));
        return;
    }
    tid = *(uint16_t *)p;

    r = bvalue_dict_get(dict, "r");
    if (!r) {
        TRACE(("'r' key missing\n"));
        return;
    }

    if ((v = bvalue_dict_get(dict, "ip")) &&
        (p = bvalue_string(v, &l)) &&
        ip_counter_update(&n->ip_counter, p, l) > 0)
        update_prefix(n, 1);

    v = bvalue_dict_get(r, "id");
    if (!v) {
        TRACE(("'r.id' key missing\n"));
        return;
    }
    id = (unsigned char *)bvalue_string(v, &l);
    if (!id || l != 20) {
        TRACE(("invalid 'r.id' key\n"));
        return;
    }

    add_node(n, id, src, addrlen);
    s = get_search(n, tid);
    if (s) {
        const unsigned char *nodes = NULL;
        const unsigned char *nodes6 = NULL;
        size_t nodes_len = 0;
        size_t nodes6_len = 0;
        struct search_node *sn;

        if (is_prefix_valid(id, src, addrlen) &&
            (sn = get_search_node(s, id))) {
            const unsigned char *s;
            size_t l;

            if ((v = bvalue_dict_get(r, "token")) &&
                (s = bvalue_string(v, &l)) &&
                !sn->token)
                search_node_set_token(sn, s, l);

            if ((v = bvalue_dict_get(r, "values")) && !sn->peers)
                search_node_set_values(sn, v);

            if ((v = bvalue_dict_get(r, "v")) && !sn->v)
                search_node_set_v(sn, v);

            if ((v = bvalue_dict_get(r, "seq")))
                bvalue_integer(v, &sn->seq);

            if ((v = bvalue_dict_get(r, "k")) &&
                (s = bvalue_string(v, &l)) && l == 32)
                memcpy(sn->k, s, 32);

            if ((v = bvalue_dict_get(r, "sig")) &&
                (s = bvalue_string(v, &l)) && l == 64)
                memcpy(sn->sig, s, 64);

            gettimeofday(&sn->reply_time, NULL);
        }

        if ((v = bvalue_dict_get(r, "nodes")) &&
            (nodes = (unsigned char *)bvalue_string(v, &nodes_len)))
            add_compact_nodes(s, nodes, nodes_len);

        if ((v = bvalue_dict_get(r, "nodes6")) &&
            (nodes6 = (unsigned char *)bvalue_string(v, &nodes6_len)))
            add_compact_nodes6(s, nodes6, nodes6_len);
    }
}

static void handle_error(struct dht_node *n, struct bvalue *dict,
                         const struct sockaddr *src, socklen_t addrlen)
{
    const struct bvalue *v, *e;
    int code;
    const char *msg;
    size_t l;
    uint16_t *tid;
    struct search *s;
    const void *p;

    e = bvalue_dict_get(dict, "e");
    if (!e) {
        TRACE(("'e' key missing\n"));
        return;
    }

    if (!(v = bvalue_list_get(e, 0)) || bvalue_integer(v, &code) ||
        !(v = bvalue_list_get(e, 1)) ||
        !(msg = (char *)bvalue_string(v, NULL))) {
        TRACE(("Malformed error message\n"));
        return;
    }

    if ((v = bvalue_dict_get(dict, "ip")) &&
        (p = bvalue_string(v, &l)) &&
        ip_counter_update(&n->ip_counter, p, l) > 0)
        update_prefix(n, 1);

    TRACE(("Error from %s: %d %s\n", sockaddr_fmt(src, addrlen), code, msg));

    if ((v = bvalue_dict_get(dict, "t")) &&
        (tid = (uint16_t *)bvalue_string(v, &l)) &&
        l == sizeof(*tid) &&
        (s = get_search(n, *tid))) {
        struct search_node *sn = s->queue;

        /* Get search node by address and mark it as errored */
        while (sn) {
            if (sn->addrlen == addrlen &&
                !sockaddr_cmp((struct sockaddr *)&sn->addr, src)) {
                TRACE(("Marking node %s from pending search as errored\n",
                       hex(sn->id)));
                timerclear(&sn->reply_time);
                if (sn->token) {
                    /* Make sure node doesn't get used for storage */
                    free(sn->token);
                    sn->token = NULL;
                }
                sn->error = code;
                break;
            }
            sn = sn->next;
        }
    }
}

#define WANT_N4 0x1
#define WANT_N6 0x2

static int dict_set_nodes(struct dht_node *n, const unsigned char *id,
                          struct bvalue *ret, int want)
{
    struct bucket_entry closest[8];
    int i, cnt;
    unsigned char nodes[26 * 8];
    unsigned char nodes6[38 * 8];
    size_t nodes_len;
    size_t nodes6_len;
    struct bvalue *v;

    cnt = get_closest(n, id, closest, 8);
    if (cnt < 0)
        return -1;

    nodes_len = 0;
    nodes6_len = 0;
    for (i = 0; i < cnt; i++) {
        switch (closest[i].addr.ss_family) {
        case AF_INET:
            memcpy(&nodes[nodes_len], closest[i].id, 20);
            memcpy(&nodes[nodes_len + 20],
                   &((struct sockaddr_in *)&closest[i].addr)->sin_addr, 4);
            memcpy(&nodes[nodes_len + 24],
                   &((struct sockaddr_in *)&closest[i].addr)->sin_port, 2);
            nodes_len += 26;
            break;
        case AF_INET6:
            memcpy(&nodes6[nodes6_len], closest[i].id, 20);
            memcpy(&nodes6[nodes6_len + 20],
                   &((struct sockaddr_in6 *)&closest[i].addr)->sin6_addr, 16);
            memcpy(&nodes6[nodes6_len + 36],
                   &((struct sockaddr_in6 *)&closest[i].addr)->sin6_port, 2);
            nodes6_len += 38;
            break;
        default:
            continue;
        }
    }

    if (want & WANT_N4) {
        v = bvalue_new_string(nodes, nodes_len);
        bvalue_dict_set(ret, "nodes", v);
    }
    if (want & WANT_N6) {
        v = bvalue_new_string(nodes6, nodes6_len);
        bvalue_dict_set(ret, "nodes6", v);
    }

    return 0;
}

static int dict_set_peers(struct dht_node *n, const unsigned char *info_hash,
                          struct bvalue *ret)
{
    struct peer_list *pl = n->peer_storage;
    struct peer *p;
    struct bvalue *values, *v;

    while (pl) {
        if (!memcmp(info_hash, pl->info_hash, 20))
            break;
        pl = pl->next;
    }

    if (!pl)
        return -1;

    values = bvalue_new_list();
    p = pl->peers;
    while (p) {
        v = bvalue_new_compact((struct sockaddr *)&p->addr, p->addrlen);
        bvalue_list_append(values, v);

        p = p->next;
    }

    bvalue_dict_set(ret, "values", values);

    return 0;
}

static int make_token_signature(const struct sockaddr *addr, socklen_t addrlen,
                                time_t t,
                                const unsigned char *secret,
                                unsigned char out[20])
{
    struct hmac_context h;

    if (addrlen < sizeof(struct sockaddr))
        return -1;

    hmac_init(&h, secret, 16);
    switch (addr->sa_family) {
    case AF_INET:
        hmac_update(&h,
                    (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr,
                    4);
        hmac_update(&h,
                    (unsigned char *)&((struct sockaddr_in *)addr)->sin_port,
                    2);
        break;
    case AF_INET6:
        hmac_update(&h,
                    (unsigned char *)&((struct sockaddr_in6 *)addr)->sin6_addr,
                    16);
        hmac_update(&h,
                    (unsigned char *)&((struct sockaddr_in6 *)addr)->sin6_port,
                    2);
        break;
    default:
        return -1;
    }

    hmac_update(&h, (unsigned char *)&t, sizeof(time_t));
    hmac_finish(&h, out);

    return 0;
}

static int dict_set_token(struct dht_node *n, const struct sockaddr *addr,
                          socklen_t addrlen, struct bvalue *ret)
{
    struct bvalue *v;
    unsigned char token[28];
    time_t t = time(NULL);

    if (make_token_signature(addr, addrlen, t, n->secret,
                             token + 8))
        return -1;
    memcpy(token, &t, 8);

    v = bvalue_new_string((unsigned char *)token, sizeof(token));
    bvalue_dict_set(ret, "token", v);

    return 0;
}

static int is_token_valid(struct dht_node *n, const unsigned char *token,
                          const struct sockaddr *addr, socklen_t addrlen)
{
    time_t t, now = time(NULL);
    unsigned char signature[20];

    memcpy(&t, token, 8);
    if (make_token_signature(addr, addrlen, t, n->secret,
                             signature))
        return 0;

    if (memcmp(token + 8, signature, sizeof(signature))) {
        TRACE(("Bad token: invalid signature\n"));
        return 0;
    }

    if ((t + 600) < now) {
        TRACE(("Bad token: expired\n"));
        return 0;
    }

    return 1;
}

static int add_peer(struct dht_node *n, const unsigned char *info_hash,
                    int port, int implied_port,
                    const struct sockaddr *addr, socklen_t addrlen)
{
    struct peer_list *pl = n->peer_storage;
    struct peer *p;

    while (pl) {
        if (!memcmp(pl->info_hash, info_hash, 20))
            break;
    }

    if (!pl) {
        pl = malloc(sizeof(struct peer_list));
        if (!pl)
            return -1;
        memcpy(pl->info_hash, info_hash, 20);
        pl->peers = NULL;
        pl->next = n->peer_storage;
        n->peer_storage = pl;
    }

    p = malloc(sizeof(struct peer));
    if (!p)
        return -1;
    memcpy(&p->addr, addr, addrlen);
    p->addrlen = addrlen;
    if (!implied_port) {
        switch (p->addr.ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)&p->addr)->sin_port = htons(port);
            break;
        case AF_INET6:
            ((struct sockaddr_in6 *)&p->addr)->sin6_port = htons(port);
            break;
        default:
            break;
        }
    }
    gettimeofday(&p->expire_time, NULL);
    timeradd(&p->expire_time, &peer_timeout, &p->expire_time);
    p->next = pl->peers;
    pl->peers = p;

    return 0;
}

static int args_get_want(const struct bvalue *args,
                         const struct sockaddr *src, socklen_t addrlen)
{
    const struct bvalue *v;

    (void)addrlen;

    if ((v = bvalue_dict_get(args, "want"))) {
        size_t i;
        int ret = 0;

        if (v->type != BVALUE_LIST)
            return -1;

        for (i = 0; i < v->l.len; i++) {
            if (v->l.array[i]->type != BVALUE_STRING)
                return -1;

            if (!strcmp((char *)v->l.array[i]->s.bytes, "n4"))
                ret |= WANT_N4;
            else if (!strcmp((char *)v->l.array[i]->s.bytes, "n6"))
                ret |= WANT_N6;
            else
                return -1;
        }

        return ret;
    }

    switch (src->sa_family) {
    case AF_INET:
        return WANT_N4;
    case AF_INET6:
        return WANT_N6;
    default:
        break;
    }

    return -1;
}

static void handle_find_node(struct dht_node *n,
                             const unsigned char *tid, size_t tid_len,
                             const struct bvalue *args,
                             const struct sockaddr *src, socklen_t addrlen)
{
    const unsigned char *target;
    const struct bvalue *v;
    struct bvalue *ret;
    size_t l;
    int want;

    if (!(v = bvalue_dict_get(args, "target")) ||
        !(target = (unsigned char *)bvalue_string(v, &l)) || l != 20) {
        TRACE(("Invalid target\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    if ((want = args_get_want(args, src, addrlen)) < 0) {
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    ret = bvalue_new_dict();
    dict_set_nodes(n, target, ret, want);
    send_response(n, tid, tid_len, ret, src, addrlen);
}

static void handle_get_peers(struct dht_node *n,
                             const unsigned char *tid, size_t tid_len,
                             const struct bvalue *args,
                             const struct sockaddr *src, socklen_t addrlen)
{
    const unsigned char *info_hash;
    struct bvalue *ret;
    const struct bvalue *v;
    size_t l;
    int want;

    if (!(v = bvalue_dict_get(args, "info_hash")) ||
        !(info_hash = (unsigned char *)bvalue_string(v, &l)) || l != 20) {
        TRACE(("Invalid info_hash\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    if ((want = args_get_want(args, src, addrlen)) < 0) {
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    ret = bvalue_new_dict();
    dict_set_nodes(n, info_hash, ret, want);
    dict_set_token(n, src, addrlen, ret);
    dict_set_peers(n, info_hash, ret);
    send_response(n, tid, tid_len, ret, src, addrlen);
}

static void handle_announce_peer(struct dht_node *n,
                                 const unsigned char *tid, size_t tid_len,
                                 const struct bvalue *args,
                                 const struct sockaddr *src, socklen_t addrlen)
{
    const unsigned char *info_hash;
    const unsigned char *token;
    const struct bvalue *v;
    size_t l;
    int implied_port = 0;
    int port = 0;

    if (!(v = bvalue_dict_get(args, "info_hash")) ||
        !(info_hash = (unsigned char *)bvalue_string(v, &l)) || l != 20 ||
        !(v = bvalue_dict_get(args, "token")) ||
        !(token = (unsigned char *)bvalue_string(v, &l)) || l != 28 ||
        !is_token_valid(n, token, src, addrlen) ||
        ((v = bvalue_dict_get(args, "implied_port")) &&
         bvalue_integer(v, &implied_port)) ||
        (!implied_port && (!(v = bvalue_dict_get(args, "port")) ||
                           bvalue_integer(v, &port)))) {
        TRACE(("Invalid argument\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    add_peer(n, info_hash, port, implied_port, src, addrlen);
    send_response(n, tid, tid_len, NULL, src, addrlen);
}

static int dict_set_put_item(struct dht_node *n, const unsigned char *hash,
                             struct bvalue *ret)
{
    struct put_item *item = n->put_storage;

    while (item) {
        if (!memcmp(hash, item->hash, 20))
            break;
        item = item->next;
    }

    if (!item)
        return -1;

    if (item->seq != -1) {
        /* mutable item */
        struct bvalue *v;

        v = bvalue_new_string(item->k, 32);
        bvalue_dict_set(ret, "k", v);
        v = bvalue_new_integer(item->seq);
        bvalue_dict_set(ret, "seq", v);
        v = bvalue_new_string(item->sig, 64);
        bvalue_dict_set(ret, "sig", v);
    }
    bvalue_dict_set(ret, "v", bvalue_copy(item->v));

    return 0;
}

static void handle_get(struct dht_node *n,
                       const unsigned char *tid, size_t tid_len,
                       const struct bvalue *args,
                       const struct sockaddr *src, socklen_t addrlen)
{
    const unsigned char *target;
    struct bvalue *ret;
    const struct bvalue *v;
    size_t l;
    int want;

    if (!(v = bvalue_dict_get(args, "target")) ||
        !(target = (unsigned char *)bvalue_string(v, &l)) || l != 20) {
        TRACE(("Invalid target\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    if ((want = args_get_want(args, src, addrlen)) < 0) {
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    ret = bvalue_new_dict();
    dict_set_nodes(n, target, ret, want);
    dict_set_token(n, src, addrlen, ret);
    dict_set_put_item(n, target, ret);
    send_response(n, tid, tid_len, ret, src, addrlen);
}

static int add_put_item(struct dht_node *n,
                        const unsigned char hash[20],
                        int seq,
                        const unsigned char *k,
                        const unsigned char *sig,
                        const struct bvalue *v)
{
    struct put_item *item = n->put_storage;

    while (item) {
        if (!memcmp(item->hash, hash, 20))
            break;
        item = item->next;
    }

    if (item) {
        /* Do not mix up mutable and immutable items */
        if ((seq == -1 && item->seq >= 0) ||
            (seq >= 0 && item->seq == -1))
            return -1;

        bvalue_free(item->v);
    } else {
        item = malloc(sizeof(struct put_item));
        if (!item)
            return -1;

        memcpy(item->hash, hash, 20);
        item->next = n->put_storage;
        n->put_storage = item;
    }

    item->v = bvalue_copy(v);
    item->seq = seq;
    if (seq > 0) {
        memcpy(item->k, k, 32);
        memcpy(item->sig, sig, 64);
    }

    gettimeofday(&item->expire_time, NULL);
    timeradd(&item->expire_time, &put_timeout, &item->expire_time);

    return 0;
}

static int verify_value(const struct bvalue *val,
                        const unsigned char *salt, size_t salt_len,
                        int seq,
                        const unsigned char k[32],
                        const unsigned char sig[64])
{
    struct bvalue *v, *dict = bvalue_new_dict();
    unsigned char buf[1024];
    int rc;

    if (salt && salt_len) {
        v = bvalue_new_string(salt, salt_len);
        bvalue_dict_set(dict, "salt", v);
    }

    v = bvalue_new_integer(seq);
    bvalue_dict_set(dict, "seq", v);

    bvalue_dict_set(dict, "v", bvalue_copy(val));

    rc = bencode_buf(dict, buf, sizeof(buf));
    if (rc < 0) {
        bvalue_free(dict);
        return -1;
    }

    bvalue_free(dict);

    return ed25519_verify(sig, buf + 1, rc - 2, k);
}

static void handle_put(struct dht_node *n,
                       const unsigned char *tid, size_t tid_len,
                       const struct bvalue *args,
                       const struct sockaddr *src, socklen_t addrlen)
{
    const unsigned char *token;
    const struct bvalue *v, *val;
    size_t l;
    unsigned char hash[20];
    sha1_context h;

    if (!(val = bvalue_dict_get(args, "v")) ||
        !(v = bvalue_dict_get(args, "token")) ||
        !(token = (unsigned char *)bvalue_string(v, &l)) || l != 28 ||
        !is_token_valid(n, token, src, addrlen)) {
        TRACE(("Invalid argument\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    sha1_starts_ret(&h);

    if ((v = bvalue_dict_get(args, "k"))) { /* mutable */
        const unsigned char *k;
        const unsigned char *salt = NULL;
        const unsigned char *sig;
        int seq;
        int cas = -1;

        if (!(k = bvalue_string(v, &l)) || l != 32 ||
            !(v = bvalue_dict_get(args, "seq")) || bvalue_integer(v, &seq) ||
            seq < 0 ||
            !(v = bvalue_dict_get(args, "sig")) ||
            !(sig = bvalue_string(v, &l)) || l != 64 ||
            ((v = bvalue_dict_get(args, "salt")) &&
             !(salt = bvalue_string(v, &l))) ||
            ((v = bvalue_dict_get(args, "cas")) &&
             (bvalue_integer(v, &cas) || cas < 0))) {
            TRACE(("Invalid argument\n"));
            send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
            return;
        }

        sha1_update_ret(&h, k, 32);
        if (salt)
            sha1_update_ret(&h, salt, l);
        sha1_finish_ret(&h, hash);

        if (cas >= 0) {
            struct put_item *item = n->put_storage;

            while (item) {
                if (!memcmp(item->hash, hash, 20) && item->seq == cas)
                    break;
                item = item->next;
            }

            if (!item) {
                TRACE(("CAS mismatch\n"));
                send_error(n, tid, tid_len, 301, "CAS mismatch", src, addrlen);
                return;
            }
        } else {
            struct put_item *item = n->put_storage;

            while (item) {
                if (!memcmp(item->hash, hash, 20))
                    break;
                item = item->next;
            }

            if (item && item->seq > seq) {
                TRACE(("Invalid sequence number\n"));
                send_error(n, tid, tid_len, 302, "Invalid sequence number", src, addrlen);
                return;
            }
        }

        switch (verify_value(val, salt, l, seq, k, sig)) {
        case -1:
            TRACE(("Value too large\n"));
            send_error(n, tid, tid_len, 205, "Value too large", src, addrlen);
            return;
        case 0:
            TRACE(("Invalid signature\n"));
            send_error(n, tid, tid_len, 206, "Invalid signature", src, addrlen);
            return;
        }

        add_put_item(n, hash, seq, k, sig, val);
    } else { /* immutable */
        unsigned char buf[1000];
        int rc;

        rc = bencode_buf(val, buf, sizeof(buf));
        if (rc < 0) {
            /* Value too large */
            TRACE(("Value too large\n"));
            send_error(n, tid, tid_len, 205, "Value too large", src, addrlen);
            return;
        }

        sha1_update_ret(&h, buf, rc);
        sha1_finish_ret(&h, hash);

        add_put_item(n, hash, -1, NULL, NULL, val);
    }

    send_response(n, tid, tid_len, NULL, src, addrlen);
}

static void handle_query(struct dht_node *n, struct bvalue *dict,
                         const struct sockaddr *src, socklen_t addrlen)
{
    const struct bvalue *v, *a;
    const void *p;
    size_t l;
    const unsigned char *tid = NULL;
    size_t tid_len = 0;
    const unsigned char *id;
    struct bucket_entry *e;
    const char *query;

    if (!(v = bvalue_dict_get(dict, "t")) ||
        !(tid = (unsigned char *)bvalue_string(v, &tid_len)) ||
        !(v = bvalue_dict_get(dict, "q")) ||
        !(query = (char *)bvalue_string(v, NULL)) ||
        !(a = bvalue_dict_get(dict, "a")) ||
        !(v = bvalue_dict_get(a, "id")) ||
        !(id = (unsigned char *)bvalue_string(v, &l)) || l != 20) {
        TRACE(("Malformed query\n"));
        send_error(n, tid, tid_len, 203, "Protocol Error", src, addrlen);
        return;
    }

    if ((v = bvalue_dict_get(dict, "ip")) &&
        (p = bvalue_string(v, &l)) &&
        ip_counter_update(&n->ip_counter, p, l) > 0)
        update_prefix(n, 1);

    TRACE(("Got query %s from %s %s\n", query, hex(id),
           sockaddr_fmt(src, addrlen)));

    e = get_bucket_entry(n, id);
    if (e) {
        gettimeofday(&e->last_seen, NULL);
        timeradd(&e->last_seen, &bucket_node_timeout, &e->next_ping);
        e->pinged = 0;

        /* updade address in case it changed */
        memcpy(&e->addr, src, addrlen);
        e->addrlen = addrlen;
    }

    if (!strcmp(query, "ping"))
        send_response(n, tid, tid_len, NULL, src, addrlen);
    else if (!strcmp(query, "find_node"))
        handle_find_node(n, tid, tid_len, a, src, addrlen);
    else if (!strcmp(query, "get_peers"))
        handle_get_peers(n, tid, tid_len, a, src, addrlen);
    else if (!strcmp(query, "announce_peer"))
        handle_announce_peer(n, tid, tid_len, a, src, addrlen);
    else if (!strcmp(query, "get"))
        handle_get(n, tid, tid_len, a, src, addrlen);
    else if (!strcmp(query, "put"))
        handle_put(n, tid, tid_len, a, src, addrlen);
    else {
        TRACE(("Unknown method: %s\n", query));
        send_error(n, tid, tid_len, 204, "Method Unknown", src, addrlen);
    }
}

void hexdump(const unsigned char *buf, size_t len, unsigned int indent,
             int (*print)(const char *fmt, ...));

void dht_node_input(struct dht_node *n, const unsigned char *data, size_t len,
                    const struct sockaddr *src, socklen_t addrlen)
{
    struct bvalue *dict;
    const struct bvalue *v;
    const char *msgtype;

    dict = bdecode_buf(data, len);
    if (!dict) {
        TRACE(("bdecode failed:\n"));
#ifdef DHT_DEBUG
        hexdump(data, len, 1, debug_printf);
#endif
        return;
    }

    v = bvalue_dict_get(dict, "y");
    if (!v) {
        TRACE(("'y' key missing\n"));
        goto release;
    }
    msgtype = (char *)bvalue_string(v, NULL);
    if (!msgtype) {
        TRACE(("'y' key not a string\n"));
        goto release;
    }

    if (!strcmp(msgtype, "r")) {
        handle_response(n, dict, src, addrlen);
    } else if (!strcmp(msgtype, "q")) {
        handle_query(n, dict, src, addrlen);
    } else if (!strcmp(msgtype, "e")) {
        handle_error(n, dict, src, addrlen);
    } else {
        TRACE(("invalid message type: %s\n", msgtype));
    }

release:
    bvalue_free(dict);
}

void dht_node_ping(struct dht_node *n, struct sockaddr *dest, socklen_t addrlen)
{
    send_query(n, "ping", n->tid++, NULL, dest, addrlen);
}

void dht_node_announce(struct dht_node *n, const unsigned char *info_hash,
                       const struct search_node *nodes,
                       int implied_port, int port)
{
    struct bvalue *args, *v;
    const struct search_node *sn = nodes;
    size_t i = 0;

    while (sn && i < 8) {
        if (sn->token) {
            args = bvalue_new_dict();

            v = bvalue_new_string(info_hash, 20);
            bvalue_dict_set(args, "info_hash", v);

            v = bvalue_new_string(sn->token, sn->token_len);
            bvalue_dict_set(args, "token", v);

            v = bvalue_new_integer(implied_port);
            bvalue_dict_set(args, "implied_port", v);

            v = bvalue_new_integer(port);
            bvalue_dict_set(args, "port", v);

            send_query(n, "announce_peer", n->tid++, args,
                       (struct sockaddr *)&sn->addr, sn->addrlen);

            i++;
        }
        sn = sn->next;
    }
}

void dht_node_put_immutable(struct dht_node *n,
                            const struct search_node *nodes,
                            const struct bvalue *val)
{
    struct bvalue *args, *v;
    const struct search_node *sn = nodes;
    size_t i = 0;

    while (sn && i < 8) {
        if (sn->token) {
            args = bvalue_new_dict();

            v = bvalue_new_string(sn->token, sn->token_len);
            bvalue_dict_set(args, "token", v);

            v = bvalue_copy(val);
            bvalue_dict_set(args, "v", v);

            send_query(n, "put", n->tid++, args,
                       (struct sockaddr *)&sn->addr, sn->addrlen);
            i++;
        }
        sn = sn->next;
    }
}

void dht_node_put_mutable(struct dht_node *n,
                          const struct search_node *nodes,
                          const unsigned char k[32],
                          const unsigned char signature[64],
                          const unsigned char *salt, size_t salt_len,
                          int seq, const struct bvalue *val)
{
    struct bvalue *args, *v;
    const struct search_node *sn = nodes;
    size_t i = 0;

    sn = nodes;
    while (sn && i < 8) {
        if (!sn->token)
            goto next;

        args = bvalue_new_dict();

        v = bvalue_new_string(salt, salt_len);
        bvalue_dict_set(args, "salt", v);

        v = bvalue_new_integer(seq);
        bvalue_dict_set(args, "seq", v);

        /*
         * Use compare-and-swap if node holds a value with an old
         * sequence number.
         */
        if (sn->seq) {
            v = bvalue_new_integer(sn->seq);
            bvalue_dict_set(args, "cas", v);
        }

        v = bvalue_copy(val);
        bvalue_dict_set(args, "v", v);

        v = bvalue_new_string(signature, 64);
        bvalue_dict_set(args, "sig", v);

        v = bvalue_new_string(sn->token, sn->token_len);
        bvalue_dict_set(args, "token", v);

        v = bvalue_new_string(k, 32);
        bvalue_dict_set(args, "k", v);

        send_query(n, "put", n->tid++, args,
                   (struct sockaddr *)&sn->addr, sn->addrlen);
        i++;

next:
        sn = sn->next;
    }
}

static void refresh_done(struct dht_node *n,
                         const struct search_node *nodes,
                         void *opaque)
{
    struct bucket *b = opaque;

    (void)n;
    (void)nodes;

    b->refresh = NULL;

    TRACE(("Refresh done\n"));
}

void dht_node_timeout(struct dht_node *n, struct timeval *tv)
{
    struct timeval now, exp;
    struct bucket *b = n->buckets;
    struct search *s = n->searches.first;

    gettimeofday(&now, NULL);

    /* Set large value in case there's no work to do, say 2 hours */
    tv->tv_sec = 2 * 60 * 60;
    tv->tv_usec = 0;
    timeradd(&now, tv, &exp);

    while (b) {
        size_t i;

        if (b->cnt == BUCKET_ENTRY_MAX) {
            for (i = 0; i < BUCKET_ENTRY_MAX; i++) {
                if (timercmp(&b->nodes[i].next_ping, &exp, <))
                    exp = b->nodes[i].next_ping;
            }
        }

        if (!b->refresh && timercmp(&b->refresh_time, &exp, <))
            exp = b->refresh_time;

        b = b->next;
    }

    while (s) {
        if (timercmp(&s->next_query, &exp, <))
            exp = s->next_query;
        s = s->next;
    }

    if (timercmp(&now, &exp, <))
        timersub(&exp, &now, tv);
    else
        timerclear(tv);
}

/*
 * Node service task:
 *  - Bucket garbage collection: ping the oldest node from each full bucket
 *  - Refresh buckets that have not been updated in a long time
 *  - Start new search iterations
 *  - Garbage collect expired storage
 */
void dht_node_work(struct dht_node *n)
{
    struct timeval now;
    struct bucket *b = n->buckets;
    struct search *s = n->searches.first;
    struct peer_list **pl = &n->peer_storage;
    struct put_item **pi = &n->put_storage;

    gettimeofday(&now, NULL);

    while (b) {
        bucket_gc(n, b, &now);
        if (!b->refresh && timercmp(&b->refresh_time, &now, <=)) {
            unsigned char id[20];

            TRACE(("Refreshing bucket %s", hex(b->first)));
            if (b->next)
                TRACE(("-%s:\n", hex(b->next->first)));
            else
                TRACE((":\n"));

            bucket_random(b, id);

            dht_node_search(n, id, FIND_NODE, refresh_done, b,
                            &b->refresh);
        }

        b = b->next;
    }

    while (s) {
        struct search *next = s->next;

        search_progress(n, s, &now);
        s = next;
    }

    while (*pl) {
        struct peer **p = &(*pl)->peers;

        while (*p) {
            if (timercmp(&(*p)->expire_time, &now, <=)) {
                struct peer *next = (*p)->next;

                free(*p);
                *p = next;
                continue;
            }

            p = &(*p)->next;
        }

        if (!(*pl)->peers) {
            struct peer_list *next = (*pl)->next;

            free(*pl);
            *pl = next;
            continue;
        }
        pl = &(*pl)->next;
    }

    while (*pi) {
        if (timercmp(&(*pi)->expire_time, &now, <=)) {
            struct put_item *next = (*pi)->next;

            bvalue_free((*pi)->v);
            free(*pi);
            *pi = next;
            continue;
        }

        pi = &(*pi)->next;
    }
}

void dht_node_cleanup(struct dht_node *n)
{
    struct bucket *b = n->buckets;
    struct search *s;
    struct peer_list *pl = n->peer_storage;
    struct put_item *pi = n->put_storage;

    while (b) {
        struct bucket *next = b->next;

        free(b);
        b = next;
    }

    while ((s = n->searches.first))
        dht_node_cancel(n, s);

    ip_counter_reset(&n->ip_counter);

    while (pl) {
        struct peer_list *next = pl->next;
        struct peer *p = pl->peers;

        while (p) {
            struct peer *next2 = p->next;

            free(p);
            p = next2;
        }
        free(pl);
        pl = next;
    }

    while (pi) {
        struct put_item *next = pi->next;

        bvalue_free(pi->v);
        free(pi);
        pi = next;
    }
}

struct bvalue *dht_node_save(const struct dht_node *n)
{
    struct bvalue *v, *dict;
    struct bvalue *bucket_list;
    struct bucket *b = n->buckets;
    size_t i;

    dict = bvalue_new_dict();
    v = bvalue_new_integer(SAVE_FILE_VERSION);
    bvalue_dict_set(dict, "version", v);
    v = bvalue_new_string(n->id, 20);
    bvalue_dict_set(dict, "id", v);

    bucket_list = bvalue_new_list();
    while (b) {
        struct bvalue *bucket = bvalue_new_dict();
        struct bvalue *node_list;

        v = bvalue_new_string(b->first, 20);
        bvalue_dict_set(bucket, "first", v);
        node_list = bvalue_new_list();
        for (i = 0; i < b->cnt; i++) {
            struct bvalue *node = bvalue_new_dict();
            struct bvalue *tm;

            v = bvalue_new_string(b->nodes[i].id, 20);
            bvalue_dict_set(node, "id", v);
            v = bvalue_new_compact((struct sockaddr *)&b->nodes[i].addr,
                                   b->nodes[i].addrlen);
            bvalue_dict_set(node, "addr", v);

            tm = bvalue_new_dict();
            v = bvalue_new_integer(b->nodes[i].last_seen.tv_sec);
            bvalue_dict_set(tm, "sec", v);
            v = bvalue_new_integer(b->nodes[i].last_seen.tv_usec);
            bvalue_dict_set(tm, "usec", v);
            bvalue_dict_set(node, "last_seen", tm);

            bvalue_list_append(node_list, node);
        }
        bvalue_dict_set(bucket, "nodes", node_list);

        bvalue_list_append(bucket_list, bucket);
        b = b->next;
    }
    bvalue_dict_set(dict, "buckets", bucket_list);

    return dict;
}

int dht_node_restore(const struct bvalue *dict, struct dht_node *n)
{
    const struct bvalue *v;
    int version;
    int ret = -1;
    const unsigned char *id;
    size_t l;
    const struct bvalue *bucket_list, *bucket;
    size_t i;
    struct bucket *b, **tail = &n->buckets;
    struct timeval now;

    gettimeofday(&now, NULL);

    if (!dict)
        return -1;

    if (!(v = bvalue_dict_get(dict, "version")) || bvalue_integer(v, &version))
        goto release;

    if (version < SAVE_FILE_VERSION)
        goto release;

    /*
     * Free current bucket list
     */
    b = n->buckets;
    while (b) {
        struct bucket *next = b->next;

        free(b);
        b = next;
    }

    if (!(v = bvalue_dict_get(dict, "id")) || !(id = bvalue_string(v, &l)) ||
        l != 20)
        goto release;
    memcpy(n->id, id, 20);

    if (!(bucket_list = bvalue_dict_get(dict, "buckets")) ||
        bucket_list->type != BVALUE_LIST)
        goto release;

    for (i = 0; (bucket = bvalue_list_get(bucket_list, i)); i++) {
        const struct bvalue *node_list, *node;
        size_t j;

        b = malloc(sizeof(struct bucket));
        if (!b)
            goto release;

        if (!(v = bvalue_dict_get(bucket, "first")) ||
            !(id = bvalue_string(v, &l)) || l != 20)
            goto release;

        memcpy(b->first, id, 20);

        if (!(node_list = bvalue_dict_get(bucket, "nodes")) ||
            node_list->type != BVALUE_LIST)
            goto release;

        for (j = 0; (node = bvalue_list_get(node_list, j)); j++) {
            const struct bvalue *tm;

            if (!(v = bvalue_dict_get(node, "id")) ||
                !(id = bvalue_string(v, &l)) || l != 20)
                goto release;
            memcpy(b->nodes[j].id, id, 20);

            if (!(v = bvalue_dict_get(node, "addr")) ||
                compact_to_sockaddr(v, (struct sockaddr *)&b->nodes[j].addr,
                                    &b->nodes[j].addrlen))
                goto release;

            if (!(tm = bvalue_dict_get(node, "last_seen")) ||
                !(v = bvalue_dict_get(tm, "sec")) ||
                bvalue_integer_l(v, &b->nodes[j].last_seen.tv_sec) ||
                !(v = bvalue_dict_get(tm, "usec")) ||
                bvalue_integer_l(v, &b->nodes[j].last_seen.tv_usec))
                goto release;

            b->nodes[j].pinged = 0;
            timerclear(&b->nodes[j].next_ping);
        }

        b->cnt = j;
        timeradd(&now, &bucket_refresh_timeout, &b->refresh_time);
        b->refresh = NULL;

        *tail = b;
        tail = &b->next;
    }
    *tail = NULL;

    ret = 0;

release:
    return ret;
}

void dht_node_set_bootstrap_callback(struct dht_node *n,
                                     bootstrap_status_t callback,
                                     void *opaque)
{
    n->bootstrap_cb = callback;
    n->bootstrap_priv = opaque;
}
