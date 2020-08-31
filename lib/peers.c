/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <string.h>

#include <dht/node.h>
#include <dht/utils.h>
#include <dht/peers.h>

struct get_peers_context
{
    unsigned char info_hash[20];
    int announce;
    int port;
    get_peers_callback callback;
    void *opaque;
};

static void gp_complete(struct dht_node *n,
                        const struct search_node *nodes,
                        void *opaque)
{
    struct get_peers_context *ctx = opaque;
    struct sockaddr_storage *peers = NULL;
    size_t count = 0;
    size_t i, j;
    const struct search_node *sn = nodes;

    (void)n;

    if (nodes && ctx->announce) {
        dht_node_announce(n, ctx->info_hash, nodes,
                          ctx->port < 0,
                          ctx->port < 0 ? 0 : ctx->port);
    }

    while (sn) {
        for (i = 0; i < sn->peer_count; i++) {
            void *tmp;

            for (j = 0; j < count; j++) {
                if (!sockaddr_cmp((struct sockaddr *)&sn->peers[i],
                                  (struct sockaddr *)&peers[j]))
                    break;
            }
            if (j != count)
                continue;

            tmp = realloc(peers, (count + 1) * sizeof(struct sockaddr_storage));
            if (!tmp)
                continue;
            peers = tmp;
            memcpy(&peers[count++], &sn->peers[i],
                   sizeof(struct sockaddr_storage));
        }

        sn = sn->next;
    }

    if (ctx->callback)
        ctx->callback(ctx->info_hash, peers, count, ctx->opaque);

    if (peers)
        free(peers);

    free(ctx);
}

int dht_get_peers(struct dht_node *node, const unsigned char info_hash[20],
                  get_peers_callback callback, void *opaque,
                  dht_search_t *handle)
{
    struct get_peers_context *ctx;
    dht_search_t h;

    ctx = malloc(sizeof(struct get_peers_context));
    if (!ctx)
        return -1;

    memcpy(ctx->info_hash, info_hash, 20);
    ctx->announce = 0;
    ctx->callback = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, info_hash, GET_PEERS, gp_complete, ctx, &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}

int dht_announce_peer(struct dht_node *node, const unsigned char info_hash[20],
                      int port, get_peers_callback callback, void *opaque,
                      dht_search_t *handle)
{
    struct get_peers_context *ctx;
    dht_search_t h;

    ctx = malloc(sizeof(struct get_peers_context));
    if (!ctx)
        return -1;

    memcpy(ctx->info_hash, info_hash, 20);
    ctx->announce = 1;
    ctx->port = port;
    ctx->callback = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, info_hash, GET_PEERS, gp_complete, ctx, &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}
