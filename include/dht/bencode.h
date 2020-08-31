/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

/*!
 * \file bencode.h
 * \brief Provides routines for parsing and formating bencoded data.
 *
 * All BitTorrent specifications use a special data serialization format
 * called bencoding. This API contains the tools necessary to parse and format
 * bencoded data.
 */

#ifndef DHT_BENCODE_H_
#define DHT_BENCODE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/*!
 * bencoding value.
 *
 * A bencoding value representation capable of holding one of 4 types:
 * "integer", "string", "list", and "dictionary".
 */
struct bvalue {
    /*!
     * Type of the value contained.
     */
    enum {
        BVALUE_INTEGER,
        BVALUE_STRING,
        BVALUE_LIST,
        BVALUE_DICTIONARY,
    } type;
    /*!
     * Type-specific data
     */
    union {
        /*!
         * Integer value
         */
        long long int i;
        /*!
         * String value
         */
        struct {
            unsigned char *bytes;   /*!< string pointer (zero-terminated) */
            size_t len;             /*!< length of the string */
        } s;
        /*!
         * List value
         */
        struct {
            struct bvalue **array;  /*!< array of elements */
            size_t len;             /*!< number of elements */
        } l;
        /*!
         * Dictionary value
         */
        struct {
            char **key;             /*!< array of keys (in lexicographical order) */
            struct bvalue **val;    /*!< array of values */
            size_t len;             /*!< number of key-value pairs */
        } d;
    };
};

/*!
 * Allocate a dictionary value.
 *
 * Builds a new empty dictionary value.
 *
 * \returns Pointer to newly allocated value, or NULL on allocation failure.
 */
struct bvalue *bvalue_new_dict(void);
/*!
 * Allocate a list value.
 *
 * Builds a new empty list value.
 *
 * \returns Pointer to newly allocated value, or NULL on allocation failure.
 */
struct bvalue *bvalue_new_list(void);
/*!
 * Allocate an integer value.
 *
 * Builds a new integer value and set it to \a i.
 *
 * \param i Initial integer value.
 * \returns Pointer to newly allocated value, or NULL on allocation failure.
 */
struct bvalue *bvalue_new_integer(long long int i);
/*!
 * Allocate a string value.
 *
 * Builds a new string value initially set to \a s.
 * This function allocates its own copy of \a s, so the memory can be reused
 * after the call. The internal string buffer is always null-terminated.
 *
 * \param s pointer to the initial string value.
 * \param len length (in bytes) of the intial string value.
 * \returns Pointer to newly allocated value, or NULL on allocation failure.
 */
struct bvalue *bvalue_new_string(const unsigned char *s, size_t len);
/*!
 * Deep copy bencoding value.
 *
 * Recursively copy \a val an all of it's children.
 *
 * \param val The value to copy.
 */
struct bvalue *bvalue_copy(const struct bvalue *val);
/*!
 * Free bencoding value.
 *
 * Recursively free \a val and all of its children.
 *
 * \param val The value to free.
 */
void bvalue_free(struct bvalue *val);

/*!
 * Append value to a list.
 *
 * Add \a val to the end of the list value \a list. \a list must be of
 * type \a BVALUE_LIST.
 *
 * \param list The list value to append to.
 * \param val The value to append.
 * \returns 0 on success, -1 on memory allocation failure.
 */
int bvalue_list_append(struct bvalue *list, struct bvalue *val);
/*!
 * Add a key-value pair to a dictionary.
 *
 * Set key \a key to value \a val in dictionary value \a dict. \a dict must
 * be of type \a BVALUE_DICTIONARY. If the key is already set in \a dict, the
 * old value is simply freed and replaced.
 *
 * \param dict The dictionary value to add the key-value pair to.
 * \param key The key to set.
 * \param val The value to corresponding to the key.
 * \returns 0 on success, -1 on memory allocation failure.
 */
int bvalue_dict_set(struct bvalue *dict, const char *key, struct bvalue *val);

/*!
 * Get dictionary value.
 *
 * Lookup a value by key in a dictionary.
 *
 * \param dict The dictionary value to get the value from. Must be of type
               \a BVALUE_DICTIONARY.
 * \param key The key the value is set to in the dictionary.
 * \returns The value or NULL if not found.
 */
const struct bvalue *bvalue_dict_get(const struct bvalue *dict, const char *key);
/*!
 * Get list value.
 *
 * Get a value by position in a list.
 *
 * \param list The list value to get the value from. Must be of type
               \a BVALUE_LIST.
 * \param pos The position of the value in the list.
 * \returns The value or NULL if \a pos is invalid.
 */
const struct bvalue *bvalue_list_get(const struct bvalue *list, size_t pos);
/*!
 * Get string value.
 *
 * Get C string pointer from a value of type \a BVALUE_STRING. The return value
 * is a pointer to the value's own internal storage. The returned string is
 * always null-terminated so it can be used in printf-like functions. However,
 * since it is designed to also store binary (non-ASCII) data, it can contain
 * embedded zeroes. This function will optionnaly return the length of the
 * string in \a len if not NULL.
 *
 * \param val The string value. Must be of type \a BVALUE_STRING.
 * \param len Optional pointer to an integer that will receive the length of
 *            the string.
 * \returns C string or NULL if \a val is invalid.
 */
const unsigned char *bvalue_string(const struct bvalue *val, size_t *len);
/*!
 * Get integer (int) value.
 *
 * Returns the integer value of a value of type \a BVALUE_INTEGER.
 *
 * \param val The integer value. Must be of type \a BVALUE_INTEGER.
 * \param intval Pointer to an int that will receive the integer value.
 * \returns 0 on success, or -1 if \a val has the wrong type or in case of
 *            overflow.
 */
int bvalue_integer(const struct bvalue *val, int *intval);
/*!
 * Get integer (long int) value.
 *
 * Returns the integer value of a value of type \a BVALUE_INTEGER.
 *
 * \param val The integer value. Must be of type \a BVALUE_INTEGER.
 * \param intval Pointer to an int that will receive the integer value.
 * \returns 0 on success, or -1 if \a val has the wrong type or in case of
 *            overflow.
 */
int bvalue_integer_l(const struct bvalue *val, long int *intval);
/*!
 * Get integer (long long int) value.
 *
 * Returns the integer value of a value of type \a BVALUE_INTEGER.
 *
 * \param val The integer value. Must be of type \a BVALUE_INTEGER.
 * \param intval Pointer to an int that will receive the integer value.
 * \returns 0 on success, or -1 if \a val has the wrong type or in case of
 *            overflow.
 */
int bvalue_integer_ll(const struct bvalue *val, long long int *intval);

/*!
 * Parse bencoded file.
 *
 * \param stream Stream to parse (FILE pointer).
 * \returns Parsed value or NULL if parsing failed.
 */
struct bvalue *bdecode_file(FILE *stream);
/*!
 * bencode value to file.
 *
 * \param val Value to encode.
 * \param stream Stream to write encoded data to.
 * \returns number of characters written to stream or -1 if write failed.
 */
int bencode_file(const struct bvalue *val, FILE *stream);

/*!
 * Parse bencoded string buffer.
 *
 * \param buf string buffer to parse.
 * \param len Length to parse.
 * \returns Parsed value or NULL if parsing failed.
 */
struct bvalue *bdecode_buf(const unsigned char *buf, size_t len);
/*!
 * bencode value to a string buffer.
 *
 * \param val Value to encode.
 * \param buf Memory buffer to write encoded data to.
 * \param len Length of the memory buffer.
 * \returns number of characters written to stream or -1 if \a buf is not large
 *          enough.
 */
int bencode_buf(const struct bvalue *val, unsigned char *buf, size_t len);
/*!
 * Allocate and bencode value to a string buffer.
 *
 * This function is analog to \ref bencode_buf, except it allocates a buffer
 * large enough to hold the output. The buffered returned in \a bufp should
 * be freed by the application when it is no longer needed.
 *
 * \param val Value to encode.
 * \param bufp Pointer to a location that will receive the address of the
 *             encoded data.
 * \returns number of characters written to stream or -1 if an error occured.
 */
int bencode_buf_alloc(const struct bvalue *val, unsigned char **bufp);

#ifdef __cplusplus
}
#endif

#endif /* BENCODE_H_ */
