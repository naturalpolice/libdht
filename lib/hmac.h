/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#ifndef HMAC_H_
#define HMAC_H_

#include "sha1.h"

struct hmac_context
{
    unsigned char k[64];
    sha1_context h;
};

void hmac_init(struct hmac_context *ctx,
               const unsigned char *secret, size_t secret_len);

void hmac_update(struct hmac_context *ctx, const unsigned char *input,
                 size_t len);

void hmac_finish(struct hmac_context *ctx, unsigned char output[20]);

void hmac_free(struct hmac_context *ctx);

#endif /* HMAC_H_ */
