/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#ifndef IP_COUNTER_H_
#define IP_COUNTER_H_

int ip_counter_update(struct ip_counter *c, const unsigned char *ip, size_t len);
int ip_counter_current(struct ip_counter *c, unsigned char ip[18]);
void ip_counter_init(struct ip_counter *c);
void ip_counter_reset(struct ip_counter *c);

#endif /* IP_COUNTER_H_ */
