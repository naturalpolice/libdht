/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>

#include <dht/node.h>
#include <dht/utils.h>
#include <dht/peers.h>

struct send_buffer
{
    struct sockaddr_storage dest;
    socklen_t addrlen;
    size_t len;
    struct send_buffer *next;
};

struct node
{
    lua_State *L;
    struct dht_node node;
    int outputref;
    int bootstrapref;
    struct {
        struct send_buffer *first;
        struct send_buffer **last;
    } send_queue;
};

struct continue_context
{
    int retval;
    struct node *n;
};

static int xmit_continue(lua_State *L, int status, lua_KContext kctx)
{
    struct continue_context *ctx = (struct continue_context *)kctx;
    struct node *n = ctx->n;
    struct send_buffer *sb;
    int ret = ctx->retval;

    (void)status;

    while ((sb = n->send_queue.first)) {
        char tmp[INET6_ADDRSTRLEN];

        lua_rawgeti(L, LUA_REGISTRYINDEX, n->outputref);
        lua_pushlstring(L, (const char *)(sb + 1), sb->len);

        switch(sb->dest.ss_family) {
        case AF_INET:
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)&sb->dest;

                lua_pushstring(L, inet_ntop(AF_INET, &sin->sin_addr, tmp,
                                            sizeof(tmp)));
                lua_pushinteger(L, ntohs(sin->sin_port));
                break;
            }
        case AF_INET6:
            {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sb->dest;

                lua_pushstring(L, inet_ntop(AF_INET6, &sin6->sin6_addr, tmp,
                                            sizeof(tmp)));
                lua_pushinteger(L, ntohs(sin6->sin6_port));
                break;
            }
            break;
        default:
            return luaL_error(L, "invalid address family");
        }

        n->send_queue.first = sb->next;
        if (!n->send_queue.first)
            n->send_queue.last = &n->send_queue.first;
        free(sb);

        lua_callk(L, 3, 0, kctx, xmit_continue);
    }

    free(ctx);
    return ret;
}

static int xmit_start(lua_State *L, struct node *n, int retval)
{
    struct continue_context *ctx;

    if (!n->send_queue.first)
        return retval;

    ctx = malloc(sizeof(*ctx));
    ctx->retval = retval;
    ctx->n = n;

    return xmit_continue(L, LUA_OK, (lua_KContext)ctx);
}

static int to_sockaddr(const char *ip, int port,
                       struct sockaddr *addr, socklen_t *addrlen)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

    if (*addrlen >= sizeof(*sin) &&
        inet_pton(AF_INET, ip, &sin->sin_addr) > 0) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
    } else if (*addrlen >= sizeof(*sin6) &&
               inet_pton(AF_INET6, ip, &sin6->sin6_addr) > 0) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
    } else
        return -1;

    return 0;
}

static int l_node_ping(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    const char *ip = luaL_checkstring(L, 2);
    int port = luaL_checkinteger(L, 3);
    struct sockaddr_storage ss;
    socklen_t addrlen = sizeof(ss);

    if (to_sockaddr(ip, port, (struct sockaddr *)&ss, &addrlen))
        luaL_error(L, "invalid address: %s", ip);

    n->L = L;
    dht_node_ping(&n->node, (struct sockaddr *)&ss, addrlen);

    return xmit_start(L, n, 0);
}

static int l_node_timeout(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    struct timeval tv;

    n->L = L;
    dht_node_timeout(&n->node, &tv);

    lua_pushnumber(L, (double)tv.tv_sec + (double)tv.tv_usec * 0.000001f);

    return 1;
}

static int l_node_work(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");

    n->L = L;
    dht_node_work(&n->node);

    return xmit_start(L, n, 0);
}

static int l_node_start(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");

    n->L = L;
    if (dht_node_start(&n->node))
        return luaL_error(L, "dht_node_start failed: %s", strerror(errno));

    return xmit_start(L, n, 0);
}

static int l_node_input(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    size_t len;
    const unsigned char *data = (unsigned char *)luaL_checklstring(L, 2, &len);
    const char *ip = luaL_checkstring(L, 3);
    int port = luaL_checkinteger(L, 4);
    struct sockaddr_storage ss;
    socklen_t addrlen = sizeof(ss);

    if (to_sockaddr(ip, port, (struct sockaddr *)&ss, &addrlen))
        luaL_error(L, "invalid address: %s", ip);

    n->L = L;
    dht_node_input(&n->node, data, len, (struct sockaddr *)&ss, addrlen);

    return xmit_start(L, n, 0);
}

static int l_node_set_bootstrap_callback(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");

    luaL_unref(L, LUA_REGISTRYINDEX, n->bootstrapref);
    lua_pushvalue(L, 2);
    n->bootstrapref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

static int l_node_save(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    struct bvalue *v;
    int rc;
    unsigned char *data;

    v = dht_node_save(&n->node);
    if (!v)
        return luaL_error(L, "dht_node_save failed");

    rc = bencode_buf_alloc(v, &data);
    if (rc < 0) {
        bvalue_free(v);
        return luaL_error(L, "bencoding failed");
    }
    bvalue_free(v);
    lua_pushlstring(L, (char *)data, rc);
    free(data);

    return 1;
}

static int l_node_restore(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    size_t len;
    const char *data = luaL_checklstring(L, 2, &len);
    struct bvalue *v;

    v = bdecode_buf((const unsigned char *)data, len);
    if (!v)
        return luaL_error(L, "bdecoding failed");

    if (dht_node_restore(v, &n->node)) {
        bvalue_free(v);
        return luaL_error(L, "dht_node_restore failed");
    }

    bvalue_free(v);

    return 0;
}

static int l_node_destroy(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    struct send_buffer *sb;

    /* release send queue */
    while ((sb = n->send_queue.first)) {
        n->send_queue.first = sb->next;
        free(sb);
    }
    n->L = L;
    dht_node_cleanup(&n->node);
    luaL_unref(L, LUA_REGISTRYINDEX, n->outputref);
    luaL_unref(L, LUA_REGISTRYINDEX, n->bootstrapref);

    return 0;
}

struct get_peers_priv
{
    lua_State *L;
    int ref;
};

static void get_peers_cb(const unsigned char info_hash[20],
                         const struct sockaddr_storage *peers,
                         size_t count,
                         void *opaque)
{
    struct get_peers_priv *priv = opaque;
    size_t i;
    lua_State *L = priv->L;

    (void)info_hash;

    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->ref);
    luaL_unref(L, LUA_REGISTRYINDEX, priv->ref);
    free(priv);

    lua_pushstring(L, hex(info_hash));

    if (!peers)
        lua_pushnil(L);
    else {
        lua_createtable(L, count, 0);
        for (i = 0; i < count; i++) {

            char tmp[INET6_ADDRSTRLEN];

            lua_createtable(L, 2, 0);
            switch(peers[i].ss_family) {
            case AF_INET:
                {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&peers[i];

                    lua_pushstring(L, inet_ntop(AF_INET, &sin->sin_addr, tmp,
                                                      sizeof(tmp)));
                    lua_rawseti(L, -2, 1);
                    lua_pushinteger(L, ntohs(sin->sin_port));
                    lua_rawseti(L, -2, 2);
                    break;
                }
            case AF_INET6:
                {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&peers[i];

                    lua_pushstring(L, inet_ntop(AF_INET6, &sin6->sin6_addr,
                                                      tmp, sizeof(tmp)));
                    lua_rawseti(L, -2, 1);
                    lua_pushinteger(L, ntohs(sin6->sin6_port));
                    lua_rawseti(L, -2, 2);
                    break;
                }
                break;
            default:
                luaL_error(L, "invalid address family");
            }
            lua_rawseti(L, -2, i + 1);
        }
    }

    lua_call(L, 2, 0);
}

static int l_get_peers(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    unsigned char infohash[20];
    const char *hex = NULL;
    struct get_peers_priv *priv;
    size_t l;
    dht_search_t handle;

    hex = luaL_checklstring(L, 2, &l);
    if (l != 40)
        return luaL_error(L, "invalid infohash");
    from_hex(hex, infohash);

    priv = malloc(sizeof(*priv));
    if (!priv)
        return luaL_error(L, "allocation error");

    priv->L = L;
    lua_pushvalue(L, 3);
    priv->ref = luaL_ref(L, LUA_REGISTRYINDEX);

    if (dht_get_peers(&n->node, infohash, get_peers_cb, priv, &handle))
        return luaL_error(L, "dht_get_peers failed: %s", strerror(errno));

    lua_pushlightuserdata(L, handle);

    return 1;
}

static int l_node_cancel(lua_State *L)
{
    struct node *n = luaL_checkudata(L, 1, "dht_node");
    dht_search_t handle = luaL_checkudata(L, 2, NULL);

    dht_node_cancel(&n->node, handle);

    return 0;
}

static const struct luaL_Reg methods[] = {
    { "ping", l_node_ping },
    { "timeout", l_node_timeout },
    { "start", l_node_start },
    { "work", l_node_work },
    { "input", l_node_input },
    { "set_bootstrap_callback", l_node_set_bootstrap_callback },
    { "save", l_node_save },
    { "restore", l_node_restore },
    { "__gc", l_node_destroy },
    { "cancel", l_node_cancel },
    { "get_peers", l_get_peers },
    { NULL, NULL }
};

static void node_send(const unsigned char *data, size_t len,
                      const struct sockaddr *dest, socklen_t addrlen,
                      void *opaque)
{
    struct node *n = opaque;
    struct send_buffer *sb = malloc(sizeof(struct send_buffer) + len);

    memcpy(&sb->dest, dest, addrlen);
    sb->addrlen = addrlen;
    sb->len = len;
    memcpy(sb + 1, data, len);
    sb->next = NULL;

    *n->send_queue.last = sb;
    n->send_queue.last = &sb->next;
}

static void bootstrap_callback(int ready, void *opaque)
{
    struct node *n = opaque;
    lua_State *L = n->L;

    lua_rawgeti(L, LUA_REGISTRYINDEX, n->bootstrapref);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_pushboolean(L, ready);
    lua_call(L, 1, 0);
}

static int l_node_create(lua_State *L)
{
    struct node *n;
    unsigned char id[20];
    const char *hex = NULL;
    size_t l;

    n = lua_newuserdata(L, sizeof(struct node));
    luaL_setmetatable(L, "dht_node");

    if (lua_type(L, 1) != LUA_TNIL) {
        hex = luaL_checklstring(L, 1, &l);
        if (l != 40)
            return luaL_error(L, "invalid node ID");
        from_hex(hex, id);
    }

    lua_pushvalue(L, 2);
    n->outputref = luaL_ref(L, LUA_REGISTRYINDEX);
    n->bootstrapref = LUA_NOREF;
    n->send_queue.first = NULL;
    n->send_queue.last = &n->send_queue.first;

    n->L = L;
    if (dht_node_init(&n->node, hex ? id : NULL, node_send, n))
        return luaL_error(L, "dht_node_init failed: %s", strerror(errno));

    dht_node_set_bootstrap_callback(&n->node, bootstrap_callback, n);

    return 1;
}

static const struct luaL_Reg functions[] = {
    { "node_create", l_node_create },
    { NULL, NULL }
};

int luaopen_dht(lua_State *L)
{
    luaL_newmetatable(L, "dht_node");
    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_rawset(L, -3);

    luaL_setfuncs(L, methods, 0);
    luaL_newlibtable(L, functions);
    luaL_setfuncs(L, functions, 0);

    return 1;
}
