/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include <dht/bencode.h>

void bvalue_free(struct bvalue *val)
{
    size_t i;

    switch (val->type) {
    case BVALUE_INTEGER:
        break;
    case BVALUE_STRING:
        free(val->s.bytes);
        break;
    case BVALUE_LIST:
        for (i = 0; i < val->l.len; i++)
            bvalue_free(val->l.array[i]);
        free(val->l.array);
        break;
    case BVALUE_DICTIONARY:
        for (i = 0; i < val->d.len; i++) {
            free(val->d.key[i]);
            bvalue_free(val->d.val[i]);
        }
        free(val->d.key);
        free(val->d.val);
        break;
    }

    free(val);
}

const struct bvalue *bvalue_dict_get(const struct bvalue *dict, const char *key)
{
    size_t i;

    if (dict->type != BVALUE_DICTIONARY)
        return NULL;

    for (i = 0; i < dict->d.len; i++) {
        if (!strcmp(dict->d.key[i], key))
            return dict->d.val[i];
    }

    return NULL;
}

const struct bvalue *bvalue_list_get(const struct bvalue *list, size_t pos)
{
    if (list->type != BVALUE_LIST)
        return NULL;

    if (pos >= list->l.len)
        return NULL;

    return list->l.array[pos];
}

const unsigned char *bvalue_string(const struct bvalue *val, size_t *len)
{
    if (val->type != BVALUE_STRING)
        return NULL;

    if (len)
        *len = val->s.len;

    return val->s.bytes;
}

int bvalue_integer(const struct bvalue *val, int *intval)
{
    if (val->type != BVALUE_INTEGER)
        return -1;

    if (val->i < INT_MIN || val->i > INT_MAX)
        return -1; /* Overflow */

    *intval = (int)val->i;

    return 0;
}

int bvalue_integer_l(const struct bvalue *val, long int *intval)
{
    if (val->type != BVALUE_INTEGER)
        return -1;

    if (val->i < LONG_MIN || val->i > LONG_MAX)
        return -1; /* Overflow */

    *intval = (long)val->i;

    return 0;
}

int bvalue_integer_ll(const struct bvalue *val, long long int *intval)
{
    if (val->type != BVALUE_INTEGER)
        return -1;

    *intval = val->i;

    return 0;
}

struct stream_ops {
    int (*peek_char)(void *);
    int (*get_char)(void *);
    int (*put_char)(int, void *);
};

static size_t stream_read(void *buf, size_t len, void *stream,
                          const struct stream_ops *ops)
{
    char *p = buf;
    int c;
    size_t l = 0;

    while (l < len) {
        c = ops->get_char(stream);
        if (c == EOF)
            break;
        p[l++] = c;
    }

    return l;
}

static size_t stream_write(const void *buf, size_t len, void *stream,
                           const struct stream_ops *ops)
{
    const char *p = buf;
    size_t l = 0;

    while (l < len) {
        if (ops->put_char(p[l], stream) == EOF)
            break;
        l++;
    }

    return l;
}

static struct bvalue *bdecode(void *stream, const struct stream_ops *ops)
{
    struct bvalue *ret;
    int c;
    void *tmp;

    ret = malloc(sizeof(struct bvalue));
    if (!ret)
        return NULL;

    switch ((c = ops->get_char(stream))) {
    case 'i':
        {
            int v = 0;
            int neg = 0;

            if ((c = ops->get_char(stream)) == '-') {
                neg = 1;
                c = ops->get_char(stream);
            }
            do {
                if (c < '0' || c > '9') {
                    free(ret);
                    return NULL;
                }
                v = (v * 10) + (c - '0');
            } while ((c = ops->get_char(stream)) != 'e');
            ret->type = BVALUE_INTEGER;
            ret->i = neg ? -v : v;
        }
        break;
    case 'l':
        {
            ret->type = BVALUE_LIST;
            ret->l.array = NULL;
            ret->l.len = 0;
            while (ops->peek_char(stream) != 'e') {
                struct bvalue *v;

                tmp = realloc(ret->l.array,
                              (ret->l.len + 1) * sizeof(struct bvalue *));
                if (!tmp) {
                    bvalue_free(ret);
                    return NULL;
                }
                ret->l.array = tmp;
                v = bdecode(stream, ops);
                if (!v) {
                    bvalue_free(ret);
                    return NULL;
                }

                ret->l.array[ret->l.len++] = v;
            }
            ops->get_char(stream); /* Consume 'e' */
        }
        break;
    case 'd':
        {
            ret->type = BVALUE_DICTIONARY;
            ret->d.key = NULL;
            ret->d.val = NULL;
            ret->d.len = 0;
            while ((c = ops->get_char(stream)) != 'e') {
                size_t l;
                char *key;
                struct bvalue *v;

                tmp = realloc(ret->d.key, (ret->d.len + 1) * sizeof(char *));
                if (!tmp) {
                    bvalue_free(ret);
                    return NULL;
                }
                ret->d.key = tmp;
                tmp = realloc(ret->d.val,
                              (ret->d.len + 1) * sizeof(struct bvalue *));
                if (!tmp) {
                    bvalue_free(ret);
                    return NULL;
                }
                ret->d.val = tmp;

                l = 0;
                do {
                    if (c < '0' || c > '9') {
                        bvalue_free(ret);
                        return NULL;
                    }
                    l = (l * 10) + (c - '0');
                } while ((c = ops->get_char(stream)) != ':');

                key = malloc(l + 1);
                if (!key) {
                    bvalue_free(ret);
                    return NULL;
                }
                if (stream_read(key, l, stream, ops) != l) {
                    free(key);
                    bvalue_free(ret);
                    return NULL;
                }
                key[l] = '\0';

                v = bdecode(stream, ops);
                if (!v) {
                    free(key);
                    bvalue_free(ret);
                    return NULL;
                }

                ret->d.key[ret->d.len] = key;
                ret->d.val[ret->d.len++] = v;
            }
        }
        break;
    default:
        if (c >= '0' && c <= '9') {
            size_t l = c - '0';

            while ((c = ops->get_char(stream)) != ':') {
                if (c < '0' || c > '9') {
                    bvalue_free(ret);
                    return NULL;
                }
                l = (l * 10) + (c - '0');
            }

            ret->type = BVALUE_STRING;
            ret->s.len = l;
            ret->s.bytes = malloc(l + 1);
            if (!ret->s.bytes) {
                free(ret);
                return NULL;
            }
            if (stream_read(ret->s.bytes, l, stream, ops) != l) {
                free(ret->s.bytes);
                free(ret);
                return NULL;
            }
            ret->s.bytes[l] = '\0';
            break;
        }
        free(ret);
        return NULL;
    }

    return ret;
}

struct bvalue *bvalue_new_dict(void)
{
    struct bvalue *v = malloc(sizeof(struct bvalue));

    if (!v)
        return NULL;

    v->type = BVALUE_DICTIONARY;
    v->d.key = NULL;
    v->d.val = NULL;
    v->d.len = 0;

    return v;
}

struct bvalue *bvalue_new_list(void)
{
    struct bvalue *v = malloc(sizeof(struct bvalue));

    if (!v)
        return NULL;

    v->type = BVALUE_LIST;
    v->l.array = NULL;
    v->l.len = 0;

    return v;
}

struct bvalue *bvalue_new_integer(long long int i)
{
    struct bvalue *v = malloc(sizeof(struct bvalue));

    if (!v)
        return NULL;

    v->type = BVALUE_INTEGER;
    v->i = i;

    return v;
}

struct bvalue *bvalue_new_string(const unsigned char *s, size_t len)
{
    struct bvalue *v = malloc(sizeof(struct bvalue));

    if (!v)
        return NULL;

    v->type = BVALUE_STRING;
    v->s.bytes = malloc(len + 1);
    memcpy(v->s.bytes, s, len);
    v->s.bytes[len] = '\0';
    v->s.len = len;

    return v;
}

int bvalue_list_append(struct bvalue *list, struct bvalue *val)
{
    void *tmp;

    tmp = realloc(list->l.array, (list->l.len + 1) * sizeof(struct bvalue *));
    if (!tmp)
        return -1;

    list->l.array = tmp;
    list->l.array[list->l.len] = val;

    list->l.len++;

    return 0;
}

int bvalue_dict_set(struct bvalue *dict, const char *key, struct bvalue *val)
{
    void *tmp;
    size_t i, j;

    for (i = 0; i < dict->d.len; i++) {
        int cmp = strcmp(key, dict->d.key[i]);

        if (cmp == 0) {
            bvalue_free(dict->d.val[i]);
            dict->d.val[i] = val;
            return 0;
        } else if (cmp < 0)
            break;
    }

    tmp = realloc(dict->d.key, (dict->d.len + 1) * sizeof(char *));
    if (!tmp)
        return -1;
    dict->d.key = tmp;
    tmp = realloc(dict->d.val, (dict->d.len + 1) * sizeof(struct bvalue *));
    if (!tmp)
        return -1;
    dict->d.val = tmp;

    for (j = dict->d.len; j > i; j--) {
        dict->d.key[j] = dict->d.key[j - 1];
        dict->d.val[j] = dict->d.val[j - 1];
    }

    dict->d.key[i] = strdup(key);
    dict->d.val[i] = val;

    dict->d.len++;

    return 0;
}

static int put_int(long long int val, void *stream,
                   const struct stream_ops *ops)
{
    long long int i = 1000000000000000000LL;
    int ret = 0;

    if(val < 0) {
        if (ops->put_char('-', stream) < 0)
            return -1;
        ret++;
        val = -val;
    }

    while(i > val)
        i /= 10;

    do {
        int digit = val / (i ? i : 1);

        if (ops->put_char('0' + digit, stream) < 0)
            return -1;
        ret++;
        val -= digit * i;
        i /= 10;
    } while (i > 0);

    return ret;
}

static int bencode(const struct bvalue *val, void *stream,
                   const struct stream_ops *ops)
{
    size_t i;
    int rc, ret = 0;

    switch (val->type) {
    case BVALUE_INTEGER:
        if (ops->put_char('i', stream) < 0)
            return -1;
        ret++;
        if ((rc = put_int(val->i, stream, ops)) < 0)
            return -1;
        ret += rc;
        if (ops->put_char('e', stream) < 0)
            return -1;
        ret++;
        break;
    case BVALUE_STRING:
        if ((rc = put_int((int)val->s.len, stream, ops)) < 0)
            return -1;
        ret += rc;
        if (ops->put_char(':', stream) < 0)
            return -1;
        ret++;
        if (stream_write(val->s.bytes, val->s.len, stream, ops) != val->s.len)
            return -1;
        ret += val->s.len;
        break;
    case BVALUE_LIST:
        if (ops->put_char('l', stream) < 0)
            return -1;
        ret++;
        for (i = 0; i < val->l.len; i++) {
            if ((rc = bencode(val->l.array[i], stream, ops)) < 0)
                return -1;
            ret += rc;
        }
        if (ops->put_char('e', stream) < 0)
            return -1;
        ret++;
        break;
    case BVALUE_DICTIONARY:
        if (ops->put_char('d', stream) < 0)
            return -1;
        ret++;
        for (i = 0; i < val->d.len; i++) {
            size_t l = strlen(val->d.key[i]);

            if ((rc = put_int((int)l, stream, ops)) < 0)
                return -1;
            ret += rc;
            if (ops->put_char(':', stream) < 0)
                return -1;
            ret++;
            if (stream_write(val->d.key[i], l, stream, ops) != l)
                return -1;
            ret += l;

            if ((rc = bencode(val->d.val[i], stream, ops)) < 0)
                return -1;
            ret += rc;
        }
        if (ops->put_char('e', stream) < 0)
            return -1;
        ret++;
        break;
    default:
        return -1;
    }

    return ret;
}

static int fpeekch(void *stream)
{
    int c = fgetc(stream);

    if (c == EOF)
        return EOF;

    ungetc(c, stream);

    return c;
}

static const struct stream_ops file_ops = {
    .peek_char = fpeekch,
    .get_char = (void *)fgetc,
    .put_char = (void *)fputc,
};

struct bvalue *bdecode_file(FILE *f)
{
    return bdecode(f, &file_ops);
}

int bencode_file(const struct bvalue *val, FILE *f)
{
    return bencode(val, f, &file_ops);
}

struct mem_stream {
    union {
        const unsigned char *rbuf;
        unsigned char *wbuf;
    } u;
    size_t pos;
    size_t len;
    int alloc;
};

static int mem_peek_char(void *stream)
{
    struct mem_stream *s = stream;

    if (s->pos == s->len)
        return EOF;

    return s->u.rbuf[s->pos];
}

static int mem_get_char(void *stream)
{
    struct mem_stream *s = stream;

    if (s->pos == s->len)
        return EOF;

    return s->u.rbuf[s->pos++];
}

static int mem_put_char(int c, void *stream)
{
    struct mem_stream *s = stream;

    if (s->pos == s->len) {
        void *tmp;

        if (!s->alloc)
            return EOF;

        tmp = realloc(s->u.wbuf, s->len * 2);
        if (!tmp)
            return EOF;
        s->u.wbuf = tmp;
        s->len *= 2;
    }
    s->u.wbuf[s->pos++] = (unsigned char)c;

    return (unsigned char)c;
}

static const struct stream_ops mem_ops = {
    .peek_char = mem_peek_char,
    .get_char = mem_get_char,
    .put_char = mem_put_char,
};

struct bvalue *bdecode_buf(const unsigned char *buf, size_t len)
{
    struct bvalue *ret;
    struct mem_stream stream;

    stream.u.rbuf = buf;
    stream.len = len;
    stream.pos = 0;
    stream.alloc = 0;

    ret = bdecode(&stream, &mem_ops);

    return ret;
}

int bencode_buf(const struct bvalue *val, unsigned char *buf, size_t len)
{
    struct mem_stream stream;

    stream.u.wbuf = buf;
    stream.len = len;
    stream.pos = 0;
    stream.alloc = 0;

    return bencode(val, &stream, &mem_ops);
}

int bencode_buf_alloc(const struct bvalue *val, unsigned char **bufp)
{
    struct mem_stream stream;
    int ret;

    stream.u.wbuf = malloc(512);
    stream.len = 512;
    stream.pos = 0;
    stream.alloc = 1;

    ret = bencode(val, &stream, &mem_ops);
    if (ret < 0) {
        free(stream.u.wbuf);
        return ret;
    }

    *bufp = stream.u.wbuf;

    return ret;
}

struct bvalue *bvalue_copy(const struct bvalue *val)
{
    struct bvalue *res = NULL;
    size_t i;

    switch (val->type) {
    case BVALUE_INTEGER:
        res = bvalue_new_integer(val->i);
        break;
    case BVALUE_STRING:
        res = bvalue_new_string(val->s.bytes, val->s.len);
        break;
    case BVALUE_LIST:
        res = bvalue_new_list();
        res->l.array = malloc(val->l.len * sizeof(struct bvalue *));
        for (i = 0; i < val->l.len; i++)
            res->l.array[i] = bvalue_copy(val->l.array[i]);
        res->l.len = i;
        break;
    case BVALUE_DICTIONARY:
        res = bvalue_new_dict();
        res->d.key = malloc(val->d.len * sizeof(char *));
        res->d.val = malloc(val->d.len * sizeof(struct bvalue *));
        for (i = 0; i < val->d.len; i++) {
            res->d.key[i] = strdup(val->d.key[i]);
            res->d.val[i] = bvalue_copy(val->d.val[i]);
        }
        res->d.len = i;
        break;
    default:
        break;
    }

    return res;
}
