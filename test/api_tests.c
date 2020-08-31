#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#include <cmocka.h>

#include "../lib/random.h"
#include "../lib/ed25519/ed25519.h"

#include <dht/node.h>
#include <dht/utils.h>
#include <dht/peers.h>
#include <dht/put.h>

struct state
{
    int sock;
    struct dht_node node;
};

static int io_run(struct state *st)
{
    struct timeval tv;
    fd_set rfds;
    int rc;

    FD_ZERO(&rfds);
    FD_SET(st->sock, &rfds);

    dht_node_timeout(&st->node, &tv);

    rc = select(st->sock + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
        fprintf(stderr, "select: %s\n", strerror(errno));
        return -1;
    }

    if (rc && FD_ISSET(st->sock, &rfds)) {
        unsigned char buf[2048];
        struct sockaddr_storage ss;
        socklen_t l = sizeof(ss);

        rc = recvfrom(st->sock, buf, sizeof(buf), 0,
                      (struct sockaddr *)&ss, &l);
        if (rc < 0) {
            fprintf(stderr, "recvfrom: %s\n", strerror(errno));
            return -1;
        }
        dht_node_input(&st->node, buf, rc, (struct sockaddr *)&ss, l);
    }

    dht_node_work(&st->node);

#ifdef TEST_COVERAGE
    __gcov_flush();
#endif

    return 0;
}

static void sock_send(const unsigned char *data, size_t len,
                      const struct sockaddr *dest, socklen_t addrlen,
                      void *opaque)
{
    int sock = *(int *)opaque;
    fd_set wfds;

    while (1) {
        int rc = sendto(sock, data, len, 0, dest, addrlen);

        if (rc >= 0)
             return;
        else if (errno != EAGAIN) {
            fprintf(stderr, "sendto %s: %s\n", sockaddr_fmt(dest, addrlen),
                    strerror(errno));
            return;
        }

        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);

        select(sock + 1, NULL, &wfds, NULL, NULL);
    }
}


struct get_peers_priv
{
    int done;
    unsigned char info_hash[20];
    struct sockaddr_storage *peers;
    size_t count;
};

static void get_peers_complete(const unsigned char info_hash[20],
                               const struct sockaddr_storage *peers,
                               size_t count, void *opaque)
{
    struct get_peers_priv *priv = opaque;

    memcpy(priv->info_hash, info_hash, 20);

    if (peers) {
        priv->peers = malloc(count * sizeof(struct sockaddr_storage));
        memcpy(priv->peers, peers, count * sizeof(struct sockaddr_storage));
        priv->count = count;
    } else {
        priv->peers = NULL;
        priv->count = count;
    }

    priv->done = 1;
}

static void announce_get_peers_test1(void **state)
{
    struct state *st = *state;
    unsigned char info_hash[20];
    struct get_peers_priv priv;
    int rc;
    size_t i;
    int portnum;

    /* Announce */
    priv.done = 0;
    portnum = random_value_uniform(65536);
    rc = from_hex("fa8f6d21eeb3948b8497439b4d540294c42653df", info_hash);
    assert_return_code(rc, 0);
    rc = dht_announce_peer(&st->node, info_hash, portnum, get_peers_complete,
                           &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_string_equal("fa8f6d21eeb3948b8497439b4d540294c42653df",
                        hex(priv.info_hash));
    assert_non_null(priv.peers);
    assert_int_not_equal(priv.count, 0);
    free(priv.peers);

    /* Get peers */
    priv.done = 0;
    rc = dht_get_peers(&st->node, info_hash, get_peers_complete, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_string_equal("fa8f6d21eeb3948b8497439b4d540294c42653df",
                        hex(priv.info_hash));
    assert_non_null(priv.peers);
    assert_int_not_equal(priv.count, 0);

    for (i = 0; i < priv.count; i++) {
        struct sockaddr_in *sin = (void *)&priv.peers[i];

        if (ntohs(sin->sin_port) == portnum)
            break;
    }
    assert_int_not_equal(i, priv.count); /* Found */
    free(priv.peers);
};

struct get_priv
{
    int done;
    struct bvalue *val;
};

static void get_complete(const struct bvalue *val, void *opaque)
{
    struct get_priv *priv = opaque;

    if (val)
        priv->val = bvalue_copy(val);
    else
        priv->val = NULL;

    priv->done = 1;
}

static void puti_complete(struct bvalue **val, void *opaque)
{
    struct get_priv *priv = opaque;

    (void)val;

    priv->done = 1;
}

static void immutable_put_get_test1(void **state)
{
    struct state *st = *state;
    struct get_priv priv;
    struct bvalue *v;
    unsigned char data[100];
    unsigned char hash[20];
    int rc;
    const unsigned char *s;
    size_t l;

    /* Immutable put */
    priv.done = 0;
    gen_random_bytes(data, 100);
    v = bvalue_new_string(data, 100);
    assert_non_null(v);
    rc = dht_put_immutable(&st->node, v, puti_complete, &priv, NULL, hash);
    assert_return_code(rc, errno);
    bvalue_free(v);
    while (!priv.done) io_run(st);

    /* Immutable get */
    priv.done = 0;
    rc = dht_get_immutable(&st->node, hash, get_complete, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_non_null(priv.val);
    assert_non_null((s = bvalue_string(priv.val, &l)));
    assert_int_equal(l, 100);
    assert_memory_equal(s, data, l);
    bvalue_free(priv.val);
};

static void create_keypair(unsigned char *public_key,
                           unsigned char *private_key)
{
    unsigned char seed[32];

    gen_random_bytes(seed, 32);
    ed25519_create_keypair(public_key, private_key, seed);
}

static void putm_callback1(struct bvalue **pval, void *opaque)
{
    struct get_priv *priv = opaque;

    assert_null(*pval);
    *pval = bvalue_new_string((unsigned char *)"Hello1", 6);

    priv->done = 1;
}

static void putm_callback2(struct bvalue **pval, void *opaque)
{
    struct get_priv *priv = opaque;
    const unsigned char *s;
    size_t l;

    assert_non_null(*pval);
    assert_non_null((s = bvalue_string(*pval, &l)));
    assert_string_equal(s, "Hello1");
    bvalue_free(*pval);

    *pval = bvalue_new_string((unsigned char *)"Hello2", 6);

    priv->done = 1;
}

static void putm_callback3(struct bvalue **pval, void *opaque)
{
    struct get_priv *priv = opaque;
    const unsigned char *s;
    size_t l;

    assert_non_null(*pval);
    assert_non_null((s = bvalue_string(*pval, &l)));
    assert_string_equal(s, "Hello2");
    bvalue_free(*pval);

    *pval = bvalue_new_string((unsigned char *)"Hello3", 6);

    priv->done = 1;
}

static void mutable_put_get_test1(void **state)
{
    struct state *st = *state;
    struct get_priv priv;
    unsigned char secret[64];
    unsigned char pubkey[32];
    unsigned char salt[8];
    const unsigned char *s;
    size_t l;
    int rc;

    create_keypair(pubkey, secret);
    gen_random_bytes(salt, sizeof(salt));

    /* Put1 */
    priv.done = 0;
    rc = dht_put_mutable(&st->node, secret, pubkey, salt, sizeof(salt),
                         putm_callback1, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);

    /* Get1 */
    priv.done = 0;
    rc = dht_get_mutable(&st->node, pubkey, salt, sizeof(salt),
                         get_complete, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_non_null(priv.val);
    assert_non_null((s = bvalue_string(priv.val, &l)));
    assert_string_equal(s, "Hello1");
    bvalue_free(priv.val);

    /* Put2 */
    priv.done = 0;
    rc = dht_put_mutable(&st->node, secret, pubkey, salt, sizeof(salt),
                         putm_callback2, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);

    /* Get2 */
    priv.done = 0;
    rc = dht_get_mutable(&st->node, pubkey, salt, sizeof(salt),
                         get_complete, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_non_null(priv.val);
    assert_non_null((s = bvalue_string(priv.val, &l)));
    assert_string_equal(s, "Hello2");
    bvalue_free(priv.val);

    /* Put3 */
    priv.done = 0;
    rc = dht_put_mutable(&st->node, secret, pubkey, salt, sizeof(salt),
                         putm_callback3, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);

    /* Get3 */
    priv.done = 0;
    rc = dht_get_mutable(&st->node, pubkey, salt, sizeof(salt),
                         get_complete, &priv, NULL);
    assert_return_code(rc, errno);
    while (!priv.done) io_run(st);
    assert_non_null(priv.val);
    assert_non_null((s = bvalue_string(priv.val, &l)));
    assert_string_equal(s, "Hello3");
    bvalue_free(priv.val);
}

static void node_save_restore_test1(void **state)
{
    struct state *st = *state;
    struct dht_node tmp;
    struct bvalue *v;
    int rc;

    v = dht_node_save(&st->node);
    assert_non_null(v);
    rc = dht_node_init(&tmp, NULL, NULL, NULL);
    assert_return_code(rc, errno);
    rc = dht_node_restore(v, &tmp);
    assert_return_code(rc, errno);
    bvalue_free(v);
    assert_memory_equal(st->node.id, tmp.id, 20);
    dht_node_cleanup(&tmp);
}

static void search_cancel_test1(void **state)
{
    struct state *st = *state;
    struct get_priv priv;
    unsigned char hash[20];
    int rc;
    dht_search_t handle;

    priv.done = 0;
    gen_random_bytes(hash, 20);
    rc = dht_get_immutable(&st->node, hash, get_complete, &priv, &handle);
    assert_return_code(rc, errno);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    io_run(st);
    assert_int_equal(priv.done, 0);
    dht_node_cancel(&st->node, handle);
    while (!priv.done) io_run(st);
    assert_null(priv.val);
};

static int teardown(void **state)
{
    struct state *st = *state;

    dht_node_cleanup(&st->node);
    close(st->sock);
    free(st);

    return 0;
}


#if IP_VERSION == 4
static int sock_bind(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    int en = 1;

    if (sock < 0)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(int))) {
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = 0;

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin))) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}
#elif IP_VERSION == 6
static int sock_bind(void)
{
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 sin6;
    int en = 1;

    if (sock < 0)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(int))) {
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &en, sizeof(int))) {
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    sin6.sin6_family = AF_INET6;
    memset(&sin6.sin6_addr, 0, 16);
    sin6.sin6_port = 0;

    if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6))) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}
#endif

static void bootstrap_status(int ready, void *opaque)
{
    *(int *)opaque = ready;
}

static int setup(void **state)
{
    struct state *st = malloc(sizeof(struct state));
    int status = 0;

    st->sock = sock_bind();
    assert_return_code(st->sock, errno);
    assert_return_code(dht_node_init(&st->node, NULL, sock_send, &st->sock),
                       errno);
    assert_return_code(dht_node_start(&st->node), errno);
    dht_node_set_bootstrap_callback(&st->node, bootstrap_status, &status);

    while (!status)
        io_run(st);

    *state = st;

    return 0;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(announce_get_peers_test1),
        cmocka_unit_test(immutable_put_get_test1),
        cmocka_unit_test(mutable_put_get_test1),
        cmocka_unit_test(node_save_restore_test1),
        cmocka_unit_test(search_cancel_test1),
    };

    return cmocka_run_group_tests_name("api" TEST_NAME_SUFFIX, tests, setup, teardown);
}
