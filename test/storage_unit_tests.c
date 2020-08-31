#include <stdlib.h>
#include <setjmp.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cmocka.h>

#define TESTING 1
struct dht_node;
struct bvalue;
static void send_response(struct dht_node *n,
                          const unsigned char *tid, size_t tid_len,
                          struct bvalue *ret,
                          const struct sockaddr *dest, socklen_t addrlen);
static void send_error(struct dht_node *n,
                       const unsigned char *tid, size_t tid_len,
                       int error_code, const char *error_msg,
                       const struct sockaddr *dest, socklen_t addrlen);

#include "../lib/node.c"
#include "../lib/put.c"

static int check_token(const LargestIntegralType value,
                       const LargestIntegralType check_value_data)
{
    const struct bvalue *dict = (void *)value;
    struct bvalue **token_ret = (void *)check_value_data;
    const struct bvalue *v;
    size_t l;

    v = bvalue_dict_get(dict, "token");
    if (!v || !bvalue_string(v, &l))
        return 0;

    if (token_ret)
        *token_ret = bvalue_copy(v);

    return 1;
}

static void send_error(struct dht_node *n,
                       const unsigned char *tid, size_t tid_len,
                       int error_code, const char *error_msg,
                       const struct sockaddr *dest, socklen_t addrlen)
{
    check_expected(error_code);
}

static void send_response(struct dht_node *n,
                          const unsigned char *tid, size_t tid_len,
                          struct bvalue *ret,
                          const struct sockaddr *dest, socklen_t addrlen)
{
    check_expected_ptr(ret);
}

static int check_peers(const LargestIntegralType value,
                       const LargestIntegralType check_value_data)
{
    const struct bvalue *dict = (void *)value;
    const char *peer_addr = (const char *)check_value_data;
    const struct bvalue *v;
    size_t i;

    v = bvalue_dict_get(dict, "values");
    if (!v || v->type != BVALUE_LIST)
        return 0;

    for (i = 0; i < v->l.len; i++) {
        const struct bvalue *entry = v->l.array[i];
        size_t l;
        const unsigned char *s = bvalue_string(entry, &l);

        if (!s) return 0;

        if (!strcmp(compactaddr_fmt(s, l), peer_addr))
            return 1;
    }

    return 0;
}

static void announce_get_peers(void **state)
{
    struct dht_node *node = *state;
    unsigned char tid[2];
    struct bvalue *args;
    struct sockaddr_in sin;
    unsigned char info_hash[20];
    struct bvalue *tok;

    gen_random_bytes(info_hash, sizeof(info_hash));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(11111);
    sin.sin_addr.s_addr = inet_addr("1.1.1.1");
    memset(tid, 0, sizeof(tid));

    args = bvalue_new_dict();
    bvalue_dict_set(args, "info_hash", bvalue_new_string(info_hash, 20));
    tok = NULL;
    expect_check(send_response, ret, check_token, &tok);
    handle_get_peers(node, tid, sizeof(tid), args,
                     (struct sockaddr *)&sin, sizeof(sin));
    assert_non_null(tok);
    bvalue_free(args);

    args = bvalue_new_dict();
    bvalue_dict_set(args, "token", tok);
    bvalue_dict_set(args, "info_hash", bvalue_new_string(info_hash, 20));
    bvalue_dict_set(args, "port", bvalue_new_integer(4444));
    expect_any(send_response, ret);
    handle_announce_peer(node, tid, sizeof(tid), args,
                         (struct sockaddr *)&sin, sizeof(sin));
    bvalue_free(args);

    args = bvalue_new_dict();
    bvalue_dict_set(args, "info_hash", bvalue_new_string(info_hash, 20));
    expect_check(send_response, ret, check_peers, "1.1.1.1:4444");
    handle_get_peers(node, tid, sizeof(tid), args,
                     (struct sockaddr *)&sin, sizeof(sin));
    bvalue_free(args);
}

static void empty_put(void **state)
{
    struct dht_node *node = *state;
    unsigned char tid[2];
    struct bvalue *args;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(11111);
    sin.sin_addr.s_addr = inet_addr("1.1.1.1");

    memset(tid, 0, sizeof(tid));

    args = bvalue_new_dict();

    expect_value(send_error, error_code, 203);
    handle_put(node, tid, sizeof(tid), args,
               (struct sockaddr *)&sin, sizeof(sin));
    bvalue_free(args);
}

static int bvalue_hash(const struct bvalue *v, unsigned char hash[20])
{
    unsigned char buf[1000];
    int rc;
    sha1_context h;

    rc = bencode_buf(v, buf, sizeof(buf));
    if (rc < 0) {
        /* Value too large */
        return -1;
    }

    sha1_ret(buf, rc, hash);

    return 0;
}

static int check_val(const LargestIntegralType value,
                     const LargestIntegralType check_value_data)
{
    const struct bvalue *dict = (void *)value;
    unsigned char *buf = (void *)check_value_data;
    const struct bvalue *v;
    const unsigned char *data;
    size_t l;

    v = bvalue_dict_get(dict, "v");
    if (!v || !(data = bvalue_string(v, &l)))
        return 0;

    return !memcmp(data, buf, l);
}

struct put_params {
    unsigned char data[100];
    unsigned char pubkey[32];
    int seq;
    unsigned char signature[64];
};

static int check_mutable(const LargestIntegralType value,
                         const LargestIntegralType check_value_data)
{
    const struct bvalue *dict = (void *)value;
    struct put_params *params = (void *)check_value_data;
    const struct bvalue *v;
    const unsigned char *data;
    size_t l;
    int seq;

    v = bvalue_dict_get(dict, "v");
    if (!v || !(data = bvalue_string(v, &l)))
        return 0;

    if (memcmp(data, params->data, l))
        return 0;

    v = bvalue_dict_get(dict, "seq");
    if (!v || bvalue_integer(v, &seq))
        return 0;

    if (seq != params->seq)
        return 0;

    v = bvalue_dict_get(dict, "k");
    if (!v || !(data = bvalue_string(v, &l)))
        return 0;

    if (l != sizeof(params->pubkey) || memcmp(data, params->pubkey, l))
        return 0;
    
    v = bvalue_dict_get(dict, "sig");
    if (!v || !(data = bvalue_string(v, &l)))
        return 0;

    if (l != sizeof(params->signature) ||
        memcmp(data, params->signature, l))
        return 0;

    return 1;
}

static void immutable_put_get(void **state)
{
    struct dht_node *node = *state;
    unsigned char tid[2];
    struct bvalue *args;
    struct sockaddr_in sin;
    unsigned char data[100];
    unsigned char target[20];
    struct bvalue *tok;
    struct bvalue *val;

    gen_random_bytes(data, sizeof(data));
    val = bvalue_new_string(data, sizeof(data));
    bvalue_hash(val, target);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(11111);
    sin.sin_addr.s_addr = inet_addr("1.1.1.1");
    memset(tid, 0, sizeof(tid));

    args = bvalue_new_dict();
    bvalue_dict_set(args, "target", bvalue_new_string(target, 20));
    tok = NULL;
    expect_check(send_response, ret, check_token, &tok);
    handle_get(node, tid, sizeof(tid), args,
               (struct sockaddr *)&sin, sizeof(sin));
    assert_non_null(tok);
    bvalue_free(args);

    args = bvalue_new_dict();
    bvalue_dict_set(args, "token", tok);
    bvalue_dict_set(args, "v", val);
    expect_any(send_response, ret);
    handle_put(node, tid, sizeof(tid), args,
               (struct sockaddr *)&sin, sizeof(sin));
    bvalue_free(args);

    args = bvalue_new_dict();
    bvalue_dict_set(args, "target", bvalue_new_string(target, 20));
    expect_check(send_response, ret, check_val, data);
    handle_get(node, tid, sizeof(tid), args,
               (struct sockaddr *)&sin, sizeof(sin));
    bvalue_free(args);
}

static void mutable_put_get(void **state)
{
    struct dht_node *node = *state;
    unsigned char tid[2];
    struct bvalue *get_args, *put_args;
    struct sockaddr_in sin;
    unsigned char target[20];
    struct bvalue *tok;
    struct bvalue *val;
    unsigned char seed[32];
    unsigned char secret[64];
    unsigned char salt[64];
    unsigned char tmp[1024];
    struct put_params params;
    int rc;
    sha1_context h;

    gen_random_bytes(params.data, sizeof(params.data));
    val = bvalue_new_string(params.data, sizeof(params.data));

    gen_random_bytes(seed, sizeof(seed));
    ed25519_create_keypair(params.pubkey, secret, seed);

    gen_random_bytes(salt, sizeof(salt));

    sha1_starts_ret(&h);
    sha1_update_ret(&h, params.pubkey, sizeof(params.pubkey));
    sha1_update_ret(&h, salt, sizeof(salt));
    sha1_finish_ret(&h, target);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(11111);
    sin.sin_addr.s_addr = inet_addr("1.1.1.1");
    memset(tid, 0, sizeof(tid));

    get_args = bvalue_new_dict();
    bvalue_dict_set(get_args, "target", bvalue_new_string(target, 20));
    tok = NULL;
    expect_check(send_response, ret, check_token, &tok);
    handle_get(node, tid, sizeof(tid), get_args,
               (struct sockaddr *)&sin, sizeof(sin));
    assert_non_null(tok);

    put_args = bvalue_new_dict();
    bvalue_dict_set(put_args, "salt", bvalue_new_string(salt, sizeof(salt)));
    params.seq = 42;
    bvalue_dict_set(put_args, "seq", bvalue_new_integer(params.seq));
    bvalue_dict_set(put_args, "v", val);
    ed25519_sign(params.signature, tmp + 1,
                 bencode_buf(put_args, tmp, sizeof(tmp)) - 2,
                 params.pubkey, secret);
    bvalue_dict_set(put_args, "sig",
                    bvalue_new_string(params.signature,
                                      sizeof(params.signature)));
    bvalue_dict_set(put_args, "k",
                    bvalue_new_string(params.pubkey, sizeof(params.pubkey)));
    bvalue_dict_set(put_args, "token", tok);
    expect_any(send_response, ret);
    handle_put(node, tid, sizeof(tid), put_args,
               (struct sockaddr *)&sin, sizeof(sin));

    expect_check(send_response, ret, check_mutable, &params);
    handle_get(node, tid, sizeof(tid), get_args,
               (struct sockaddr *)&sin, sizeof(sin));

    bvalue_free(get_args);
    bvalue_free(put_args);
}

static int setup(void **state)
{
    struct dht_node *node = malloc(sizeof(struct dht_node));

    dht_node_init(node, NULL, NULL, NULL);

    *state = node;

    return 0;
}

static int teardown(void **state)
{
    struct dht_node *node = *state;

    dht_node_cleanup(node);

    return 0;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(announce_get_peers),
        cmocka_unit_test(empty_put),
        cmocka_unit_test(immutable_put_get),
        cmocka_unit_test(mutable_put_get),
    };

    return cmocka_run_group_tests_name("storage", tests, setup, teardown);
}
