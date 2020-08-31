/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

/*!
 * \file utils.h
 * \brief DHT utilities.
 */

#ifndef DHT_UTILS_H_
#define DHT_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
typedef int socklen_t;
#include <winsock2.h>
#include <ws2ipdef.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

/*!
 * Return the hexadecimal representation of a 160-bit value.
 *
 * Formats the given binary info-hash into an hexadecimal string. The
 * string is returned in a statically allocated buffer, which subsequent
 * calls will overwrite and is therefore not reentrant.
 *
 * \param id The 160-bit value to convert.
 * \returns Hexadecimal string.
 */
const char *hex(const unsigned char id[20]);
/*!
 * Convert a hexadecimal representation string to a 160-bit value.
 *
 * Scans the hexadecimal string \a s and converts it to a binary info-hash.
 *
 * \param s The hexadecimal string.
 * \param id The buffer into which the info-hash will be returned.
 * \returns 0 on success, -1 if the string is invalid.
 */
int from_hex(const char *s, unsigned char id[20]);

/*!
 * Format socket address.
 *
 * Returns the socket address as a human-readable string. This function
 * supports \a AF_INET and \a AF_INET6 socket address families. The string
 * is returned in a statically allocated buffer, which subsequent calls will
 * overwrite, and is therefore not reentrant.
 *
 * \param sa The socket address
 * \param addrlen Length of the socket address structure
 * \returns The address string.
 */
const char *sockaddr_fmt(const struct sockaddr *sa, socklen_t addrlen);

/*!
 * Compare two socket addresses.
 *
 * \param s1 First socket address.
 * \param s2 Second socket address.
 * \returns -1 if s1 < s2, 0 if s1 == s2, 1 if s1 > s2.
 */
int sockaddr_cmp(const struct sockaddr *s1, const struct sockaddr *s2);

/*!
 * Format compact address information.
 *
 * Returns the given compact address address information as a human-readable
 * string. A compact address is a 4-byte IPv4 address in network byte order
 * followed by a 2-byte port number in network byte order, or a 16-byte IPv6
 * address in network byte order followed by a 2-byte port number in network
 * byte order.
 *
 * \param ip The compact address string buffer
 * \param len Length of the compact address string.
 * \returns The address string of NULL if the compact address is invalid.
 */
const char *compactaddr_fmt(const unsigned char *ip, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DHT_UTILS_H_ */
