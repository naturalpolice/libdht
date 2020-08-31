/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stdlib.h>

#include "random.h"

#if defined(_WIN32)
# include <windows.h>
# include <wincrypt.h>
int gen_random_bytes(unsigned char *buf, size_t len)
{
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
        return -1;

    if (!CryptGenRandom(prov, len, buf))  {
        CryptReleaseContext(prov, 0);
        return -1;
    }

    CryptReleaseContext(prov, 0);

    return 0;
}
#elif defined(__GLIBC__) && defined(__linux__)
# if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24
# include <sys/random.h>
int gen_random_bytes(unsigned char *buf, size_t len)
{
    if (getrandom(buf, len, 0) < 0)
        return -1;

    return 0;
}
# else
# include <sys/syscall.h>
int gen_random_bytes(unsigned char *buf, size_t len)
{
    if (syscall(SYS_getrandom, buf, len, 0) < 0)
        return -1;

    return 0;
}
# endif
#else
# include <unistd.h>
# include <fcntl.h>
int gen_random_bytes(unsigned char *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0)
        return -1;

    read(fd, buf, len);
    close(fd);

    return 0;
}
#endif
uint32_t random_value_uniform(uint32_t max)
{
    uint32_t min;
    uint32_t r;

    min = (1U + -max) % max;
    do {
        gen_random_bytes((unsigned char *)&r, sizeof(r));
    } while (r < min);

    return r % max;
}
