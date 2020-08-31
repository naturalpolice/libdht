/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <dht/utils.h>

const char *hex(const unsigned char id[20])
{
    static char buf[41];
    unsigned int i, j;

    for (i = 0, j = 0; i < 20; i++) {
        buf[j++] = (id[i] >> 4) >= 0xa ? 'a' + (id[i] >> 4) - 0xa :
                                         '0' + (id[i] >> 4);
        buf[j++] = (id[i] & 0xf) >= 0xa ? 'a' + (id[i] & 0xf) - 0xa :
                                          '0' + (id[i] & 0xf);
    }

    return buf;
}

int from_hex(const char *s, unsigned char id[20])
{
    int i;

    for (i = 0; i < 20; i++) {
        int c = s[i << 1];

        if (c >= '0' && c <= '9')
            id[i] = (c - '0') << 4;
        else if (c >= 'a' && c <= 'f')
            id[i] = ((c - 'a') + 10) << 4;
        else if (c >= 'A' && c <= 'F')
            id[i] = ((c - 'A') + 10) << 4;
        else
            return -1;

        c = s[(i << 1) + 1];
        if (c >= '0' && c <= '9')
            id[i] |= (c - '0');
        else if (c >= 'a' && c <= 'f')
            id[i] |= (c - 'a') + 10;
        else if (c >= 'A' && c <= 'F')
            id[i] |= (c - 'A') + 10;
        else
            return -1;
    }

    return 0;
}

int sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2)
{
    int cmp = s2->sa_family - s1->sa_family;

    if (cmp)
        return cmp;

    switch (s1->sa_family) {
    case AF_INET:
        {
            const struct sockaddr_in *sin1 = (struct sockaddr_in *)s1;
            const struct sockaddr_in *sin2 = (struct sockaddr_in *)s2;

            cmp = memcmp(&sin1->sin_addr, &sin2->sin_addr,
                         sizeof(struct in_addr));
            if (cmp)
                return cmp;

            cmp = ntohs(sin1->sin_port) - ntohs(sin2->sin_port);
            if (cmp)
                return cmp;
        }
        break;
    case AF_INET6:
        {
            const struct sockaddr_in6 *sin6_1 = (struct sockaddr_in6 *)s1;
            const struct sockaddr_in6 *sin6_2 = (struct sockaddr_in6 *)s2;

            cmp = memcmp(&sin6_1->sin6_addr,
                         &sin6_2->sin6_addr,
                         sizeof(struct in6_addr));
            if (cmp)
                return cmp;

            cmp = ntohs(sin6_1->sin6_port) - ntohs(sin6_2->sin6_port);
            if (cmp)
                return cmp;
        }
        break;
    default:
        break;
    }

    return 0;
}

const char *sockaddr_fmt(const struct sockaddr *sa, socklen_t addrlen)
{
    static char ret[INET6_ADDRSTRLEN + 10];
    char buf[INET6_ADDRSTRLEN];

    if (addrlen < sizeof(struct sockaddr))
        return NULL;

    switch (sa->sa_family) {
    case AF_INET:
        {
            const struct sockaddr_in *sin = (struct sockaddr_in *)sa;

            if (addrlen < sizeof(*sin))
                return NULL;

            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            snprintf(ret, sizeof(ret), "%s:%d", buf, ntohs(sin->sin_port));
        }
        break;
    case AF_INET6:
        {
            const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

            if (addrlen < sizeof(*sin6))
                return NULL;

            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
            snprintf(ret, sizeof(ret), "[%s]:%d", buf, ntohs(sin6->sin6_port));
        }
        break;
    default:
        return NULL;
    }

    return ret;
}

const char *compactaddr_fmt(const unsigned char *ip, size_t len)
{
    static char ret[INET6_ADDRSTRLEN + 10];
    char buf[INET6_ADDRSTRLEN];

    switch (len) {
    case 6:
        inet_ntop(AF_INET, ip, buf, sizeof(buf));
        snprintf(ret, sizeof(ret), "%s:%d", buf,
                 ntohs(*(unsigned short *)(ip + 4)));
        break;
    case 18:
        inet_ntop(AF_INET6, ip, buf, sizeof(buf));
        snprintf(ret, sizeof(ret), "[%s]:%d", buf,
                 ntohs(*(unsigned short *)(ip + 16)));
        break;
    default:
        return NULL;
    }

    return ret;
}
