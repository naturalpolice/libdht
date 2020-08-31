/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <string.h>

#include "hmac.h"

void hmac_init(struct hmac_context *ctx,
               const unsigned char *secret, size_t secret_len)
{
    unsigned char tmp[64];
    size_t i;

    if (secret_len > 64) {
        sha1_context h;

        sha1_starts_ret(&h);
        sha1_update_ret(&h, secret, secret_len);
        sha1_finish_ret(&h, ctx->k);
        for (i = 20; i < 64; i++)
            ctx->k[i] = 0;
    } else {
        memcpy(ctx->k, secret, secret_len);
        for (i = secret_len; i < 64; i++)
            ctx->k[i] = 0;
    }

    sha1_starts_ret(&ctx->h);

    for (i = 0; i < sizeof(tmp); i++)
        tmp[i] = ctx->k[i] ^ 0x36; /* k ^ ipad */

    sha1_update_ret(&ctx->h, tmp, sizeof(tmp));
}

void hmac_update(struct hmac_context *ctx, const unsigned char *input,
                 size_t len)
{
    sha1_update_ret(&ctx->h, input, len);
}

void hmac_finish(struct hmac_context *ctx, unsigned char output[20])
{
    sha1_context h;
    unsigned char inner[20];
    unsigned char tmp[64];
    size_t i;

    sha1_finish_ret(&ctx->h, inner);
    sha1_free(&ctx->h);

    for (i = 0; i < sizeof(tmp); i++)
        tmp[i] = ctx->k[i] ^ 0x5c; /* k ^ opad */

    sha1_starts_ret(&h);
    sha1_update_ret(&h, tmp, 64);
    sha1_update_ret(&h, inner, 20);
    sha1_finish_ret(&h, output);
}

void hmac_free(struct hmac_context *ctx)
{
    memset(&ctx->k, 0, 64);
}
