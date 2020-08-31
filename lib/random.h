/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#ifndef RANDOM_H_
#define RANDOM_H_

#include <stdint.h>

int gen_random_bytes(unsigned char *buf, size_t len);
uint32_t random_value_uniform(uint32_t max);

#endif /* RANDOM_H_ */
