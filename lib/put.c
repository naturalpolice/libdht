/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stdlib.h>
#include <string.h>

#include <dht/node.h>
#include <dht/utils.h>
#include <dht/put.h>

#include "sha1.h"
#include "ed25519/ed25519.h"

struct get_immutable_context
{
    unsigned char target[20];
    get_callback get_cb;
    void *opaque;
};

static int hash_value(const struct bvalue *val,
                      unsigned char hash[20])
{
    int rc;
    unsigned char buf[1000];

    rc = bencode_buf(val, buf, sizeof(buf));
    if (rc < 0) {
        /* Value too large */
        return -1;
    }

    sha1_ret(buf, rc, hash);

    return 0;
}

static void get_immutable_complete(struct dht_node *n,
                                   const struct search_node *nodes,
                                   void *opaque)
{
    struct get_immutable_context *ctx = opaque;
    const struct search_node *sn = nodes;

    (void)n;

    /* Select value with valid hash */
    while (sn) {
        unsigned char hash[20];

        if (sn->v &&
            !hash_value(sn->v, hash) &&
            !memcmp(hash, ctx->target, 20))
            break;

        sn = sn->next;
    }

    ctx->get_cb(sn ? sn->v : NULL, ctx->opaque);

    free(ctx);
}

int dht_get_immutable(struct dht_node *node, const unsigned char hash[20],
                      get_callback callback, void *opaque,
                      dht_search_t *handle)
{
    struct get_immutable_context *ctx;
    dht_search_t h;

    ctx = malloc(sizeof(struct get_immutable_context));
    if (!ctx)
        return -1;

    memcpy(ctx->target, hash, 20);
    ctx->get_cb = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, hash, GET, get_immutable_complete, ctx, &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}

static int hash_pubkey(const unsigned char pubkey[32],
                       const unsigned char *salt, size_t salt_len,
                       unsigned char hash[20])
{
    sha1_context sha1;

    if (salt_len > 64)
        return -1;

    sha1_starts_ret(&sha1);
    sha1_update_ret(&sha1, pubkey, 32);
    sha1_update_ret(&sha1, salt, salt_len);
    sha1_finish_ret(&sha1, hash);

    return 0;
}

static int verify_signature(const struct bvalue *val,
                            const unsigned char *salt, size_t salt_len,
                            int seq,
                            const unsigned char *k,
                            const unsigned char *signature)
{
    struct bvalue *v, *dict = bvalue_new_dict();
    unsigned char buf[1024];
    int rc;
    int ret;

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

    ret = ed25519_verify(signature, buf + 1, rc - 2, k);
    bvalue_free(dict);

    return ret;
}

struct get_mutable_context
{
    unsigned char target[20];
    unsigned char salt[64];
    size_t salt_len;
    get_callback get_cb;
    void *opaque;
};

static void get_mutable_complete(struct dht_node *n,
                                 const struct search_node *nodes,
                                 void *opaque)
{
    struct get_mutable_context *ctx = opaque;
    const struct search_node *sn = nodes;
    const struct search_node *r = NULL;

    (void)n;

    /* Select value with most up to date sequence no */
    while (sn) {
        unsigned char hash[20];

        if (sn->v &&
            !hash_pubkey(sn->k, ctx->salt, ctx->salt_len, hash) &&
            !memcmp(hash, ctx->target, 20) &&
            verify_signature(sn->v, ctx->salt, ctx->salt_len, sn->seq,
                             sn->k, sn->sig) > 0) {
            if (!r || sn->seq > r->seq)
                r = sn;
        }

        sn = sn->next;
    }

    ctx->get_cb(r ? r->v : NULL, ctx->opaque);

    free(ctx);
}

int dht_get_mutable(struct dht_node *node,
                    const unsigned char pubkey[32],
                    const unsigned char *salt, size_t salt_len,
                    get_callback callback, void *opaque,
                    dht_search_t *handle)
{
    struct get_mutable_context *ctx;
    dht_search_t h;

    ctx = malloc(sizeof(struct get_mutable_context));
    if (!ctx)
        return -1;

    if (hash_pubkey(pubkey, salt, salt_len, ctx->target)) {
        free(ctx);
        return -1;
    }
    memcpy(ctx->salt, salt, salt_len);
    ctx->salt_len = salt_len;
    ctx->get_cb = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, ctx->target, GET, get_mutable_complete, ctx,
                        &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}

struct put_immutable_context
{
    struct bvalue *val;
    put_immutable_callback put_cb;
    void *opaque;
};

static void put_immutable_complete(struct dht_node *n,
                                   const struct search_node *nodes,
                                   void *opaque)
{
    struct put_immutable_context *ctx = opaque;

    if (!nodes) {
        ctx->put_cb(-1, ctx->opaque);
        bvalue_free(ctx->val);
        free(ctx);
        return;
    }

    dht_node_put_immutable(n, nodes, ctx->val);
    bvalue_free(ctx->val);
    ctx->put_cb(0, ctx->opaque);
    free(ctx);
}

int dht_put_immutable(struct dht_node *node, const struct bvalue *v,
                      put_immutable_callback callback, void *opaque,
                      dht_search_t *handle, unsigned char hash[20])
{
    struct put_immutable_context *ctx;
    dht_search_t h;

    if (hash_value(v, hash))
        return -1;

    ctx = malloc(sizeof(struct get_immutable_context));
    if (!ctx)
        return -1;

    ctx->val = bvalue_copy(v);
    ctx->put_cb = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, hash, GET, put_immutable_complete, ctx, &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}

struct put_mutable_context
{
    unsigned char target[20];
    unsigned char salt[64];
    size_t salt_len;
    unsigned char k[32];
    unsigned char sk[64];
    put_mutable_callback put_cb;
    void *opaque;
};

static int sign_value(const struct bvalue *val,
                      const unsigned char *salt, size_t salt_len,
                      int seq,
                      const unsigned char *sk,
                      const unsigned char *k,
                      unsigned char signature[64])
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

    /*
     * Only sign the concatenated salt, seq and v values,
     * not the whole dict: only sign what's inside 'd' and 'e'
     */
    ed25519_sign(signature, buf + 1, rc - 2, k, sk);
    bvalue_free(dict);

    return 0;
}

static void put_mutable_complete(struct dht_node *n,
                                 const struct search_node *nodes,
                                 void *opaque)
{
    struct put_mutable_context *ctx = opaque;
    const struct search_node *sn = nodes;
    const struct search_node *r = NULL;
    int seq = 0;
    struct bvalue *val = NULL;

    if (!nodes) {
        ctx->put_cb(NULL, ctx->opaque);
        free(ctx);
        return;
    }

    /* Select value with most up to date sequence no */
    while (sn) {
        unsigned char hash[20];

        if (sn->v &&
            !hash_pubkey(sn->k, ctx->salt, ctx->salt_len, hash) &&
            !memcmp(hash, ctx->target, 20) &&
            verify_signature(sn->v, ctx->salt, ctx->salt_len, sn->seq,
                             sn->k, sn->sig) > 0) {
            if (!r || sn->seq > r->seq)
                r = sn;
        }

        sn = sn->next;
    }

    /* auto-select sequence number */
    if (r) {
        seq = r->seq + 1;
        val = bvalue_copy(r->v);
    }

    ctx->put_cb(&val, ctx->opaque);
    if (val) {
        unsigned char signature[64];

        sign_value(val, ctx->salt, ctx->salt_len, seq,
                   ctx->sk, ctx->k, signature);
        dht_node_put_mutable(n, nodes, ctx->k, signature,
                             ctx->salt, ctx->salt_len, seq,
                             val);

        bvalue_free(val);
    }

    free(ctx);
}

int dht_put_mutable(struct dht_node *node,
                    const unsigned char secret[64],
                    const unsigned char pubkey[32],
                    const unsigned char *salt, size_t salt_len,
                    put_mutable_callback callback, void *opaque,
                    dht_search_t *handle)
{
    struct put_mutable_context *ctx;
    dht_search_t h;

    ctx = malloc(sizeof(struct put_mutable_context));
    if (!ctx)
        return -1;

    if (hash_pubkey(pubkey, salt, salt_len, ctx->target)) {
        free(ctx);
        return -1;
    }
    memcpy(ctx->salt, salt, salt_len);
    ctx->salt_len = salt_len;
    memcpy(ctx->sk, secret, 64);
    memcpy(ctx->k, pubkey, 32);
    ctx->put_cb = callback;
    ctx->opaque = opaque;

    if (dht_node_search(node, ctx->target, GET, put_mutable_complete, ctx,
                        &h)) {
        free(ctx);
        return -1;
    }

    if (handle)
        *handle = h;

    return 0;
}
