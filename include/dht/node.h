/*
 * Copyright (c) 2020 naturalpolice
 * SPDX-License-Identifier: MIT
 *
 * Licensed under the MIT License (see LICENSE).
 */

/*!
 * \file node.h
 * \brief API for running a DHT node.
 *
 * This file defines low-level methods for a \ref dht_node object.
 */

#ifndef DHT_NODE_H_
#define DHT_NODE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#ifdef _WIN32
typedef int socklen_t;
#include <winsock2.h>
#include <ws2ipdef.h>
#else
#include <sys/socket.h>
#endif

#include "bencode.h"

/*!
 * Type of DHT search.
 */
enum dht_search_type {
    FIND_NODE,
    GET_PEERS,
    GET,
};

/*!
 * Search node.
 *
 * This structure is allocated by the node for each node encountered in the
 * course of a DHT search. Elements are chained together and sorted by
 * increasing distance with the search target.
 */
struct search_node {
    unsigned char id[20];           /*!< Node identifier */
    struct sockaddr_storage addr;   /*!< Node address */
    socklen_t addrlen;              /*!< Length of \a addr field */
    struct timeval reply_time;      /*!< Query reply time */
    struct timeval next_query;      /*!< When to send next query */
    int queried;                    /*!< Number of queries sent with no reply */
    unsigned char *token;           /*!< Storage token */
    size_t token_len;               /*!< Length of token string */
    struct search_node *next;       /*!< Next node in the list */
    struct sockaddr_storage *peers; /*!< Array of peer addresses */
    struct bvalue *v;               /*!< value received in reply to get query */
    int seq;                        /*!< \a v's sequence number */
    size_t peer_count;              /*!< Number of entries in \a peers array */
    int error;                      /*!< Error code if node query failed */
    unsigned char k[32];            /*!< ed25519 public key of stored value */
    unsigned char sig[64];          /*!< signature of stored value */
};

struct dht_node;

/*!
 * Search complete callback.
 *
 * This callback is called when a DHT search completes.
 *
 * \param n The node handling the search.
 * \param nodes Linked list of nodes found during the search. Sorted by
 *              increasing distance. If NULL, the search either returned no
 *              nodes or was cancelled.
 * \param opaque User data pointer passed to \ref dht_node_search.
 */
typedef void (*search_complete_t)(struct dht_node *n,
                                  const struct search_node *nodes,
                                  void *opaque);

/*!
 * Node output callback.
 *
 * User-defined callback for sending UDP datagrams to a remote node.
 *
 * \param data Pointer to the data buffer to send.
 * \param len Length of the data buffer to send.
 * \param dest Destination address
 * \param addrlen Length of the \a dest parameter.
 * \param opaque User data pointer passed to \ref dht_node_init.
 */
typedef void (*node_output_t)(const unsigned char *data, size_t len,
                              const struct sockaddr *dest, socklen_t addrlen,
                              void *opaque);

/*!
 * Bootstrap status notification callback
 *
 * User-defined callback called when the node boostrap status changes.
 * When \a ready is non-zero, the node is ready to handle new DHT searches.
 * When \a ready is zero, the node is bootstraping.
 *
 * \param ready Whether the node is ready.
 * \param opaque User data pointer passed to
 *               \ref dht_node_set_bootstrap_callback.
 */
typedef void (*bootstrap_status_t)(int ready, void *opaque);

/*!
 * External IP counter entry.
 */
struct ip_counter_entry {
    unsigned char ip[18];           /*!< external IP address in compact form */
    size_t len;                     /*!< Length of \a ip field */
    unsigned int count;             /*!< Number of times seen */
    struct ip_counter_entry *next;  /*!< Next entry */
};

/*!
 * External IP counter.
 */
struct ip_counter {
    unsigned int total;                 /*!< Total external IP address count */
    struct timeval heat_start;          /*!< Count start time */
    struct ip_counter_entry *entries;   /*!< External IP address entries */
};

struct bucket;
struct search;
struct peer_list;
struct put_item;

/*!
 * DHT node object.
 */
struct dht_node {
    unsigned char id[20];                   /*!< DHT node identifier */
    node_output_t output;                   /*!< Datagram output function */
    void *opaque;                           /*!< Output callback user data */
    struct bucket *buckets;                 /*!< Bucket list */
    struct {
        struct search *first;
        struct search **tail;
    } searches;                             /*!< List of pending searches */
    uint16_t tid;                           /*!< Transaction ID generation
                                                 counter */
    struct ip_counter ip_counter;           /*!< External IP counter */
    unsigned char secret[16];               /*!< Secret for token generation */
    struct peer_list *peer_storage;         /*!< Peer list storage */
    struct put_item *put_storage;           /*!< Put data storage */
    struct search *bootstrap;               /*!< Bootstrap search handle */
    bootstrap_status_t bootstrap_cb;        /*!< Bootstrap status callback */
    void *bootstrap_priv;                   /*!< Bootstrap callback user data */
};

/*!
 * Search handle.
 *
 * Handle to a pending DHT search.
 */
typedef struct search *dht_search_t;

/*!
 * Initialize DHT node.
 *
 * Initializes a \ref dht_node structure with the given node ID \a id. If the
 * \a id parameter is NULL, the node ID will be generated randomly. To remain
 * platform independent, the library does not handle network operations by
 * itself, therefore the user needs to provide \a output, a callback that takes
 * care of sending UDP datagrams over the network.
 * A very basic implementation of \a output could be:
 * \code{.c}
 * static void output(const unsigned char *data, size_t len,
 *                    const struct sockaddr *dest, socklen_t addrlen,
 *                    void *opaque)
 * {
 *     sendto(*(int *)opaque, data, len, 0, dest, addrlen);
 * }
 * \endcode
 *
 * \param n Empty node structure to initialize.
 * \param id Node identifier to use.
 * \param output Datagram output callback.
 * \param opaque Opaque pointer that will be passed to the output callback.
 * \returns 0 on success or -1 on allocation error.
 */
int dht_node_init(struct dht_node *n, const unsigned char *id,
                  node_output_t output, void *opaque);

/*!
 * Start DHT node.
 *
 * Starts servicing the DHT node. Bootstrap node if the routing table is empty.
 * Changing the node's ID or restoring a previous state must be done before
 * calling this function.
 *
 * \param n The node to start.
 */
int dht_node_start(struct dht_node *n);

/*!
 * Input a received UDP datagram
 *
 * This function must be called upon reception of a UDP datagram for
 * the node. Note that his function may bring the node timeout forward.
 * (see \ref dht_node_timeout).
 *
 * \param n The DHT node.
 * \param data Data received.
 * \param len Length of received data.
 * \param src Sender address.
 * \param addrlen Length of the \a src parameter.
 */
void dht_node_input(struct dht_node *n, const unsigned char *data, size_t len,
                    const struct sockaddr *src, socklen_t addrlen);

/*!
 * Ping remote node.
 *
 * Sends a ping query to the specified host. Querying a node known by address
 * will help speed-up the bootstrap process: if the remote hosts responds, it
 * will immediately be added to the routing table and will be used in subsequent
 * DHT searches.
 *
 * \param n The DHT node.
 * \param dest Address of the DHT node to ping.
 * \param addrlen Length of the \a dest parameter.
 */
void dht_node_ping(struct dht_node *n, struct sockaddr *dest,
                   socklen_t addrlen);

/*!
 * Get node timeout.
 *
 * Returns the amount of time after which the node needs to be serviced (by
 * calling \ref dht_node_work).
 *
 * \param n The DHT node.
 * \param tv A pointer to a timeval structure in which the timeout value will be returned.
 */
void dht_node_timeout(struct dht_node *n, struct timeval *tv);

/*!
 * Service the node
 *
 * The user is required to call this function every so often to perform
 * maintenance work (routing table updates) on the node or make progress
 * on pending searches. It is recommended to call this function every second
 * or use \ref dht_node_timeout to figure out when to call.
 *
 * \param n The DHT node.
 */
void dht_node_work(struct dht_node *n);

/*!
 * Cleanup DHT node.
 *
 * Cleans up the \ref dht_node and frees all ressources used by the node. All
 * the pending searches will be cancelled.
 *
 * \param n The DHT node.
 */
void dht_node_cleanup(struct dht_node *n);

/*!
 * Start a search on the DHT.
 *
 * Start a recursive search on the DHT. There are multiple types of search
 * (\p FIND_NODE, \p GET_PEERS and \p GET), each using a different query method
 * (respectively \a find_node, \a get_peers, and \a get), but the search
 * algorithm remains the same in all cases. The returned search handle can be
 * used to cancel a pending search with \ref dht_node_cancel.
 * The search completes when no nodes can be found closer to the target ID, the
 * \ref search_complete_t callback will then be called with a list of all the
 * nodes found during the search.
 * This is a low-level interface, consider using functions in \ref peers.h or
 * \ref put.h instead.
 * The returned search handle becomes invalid after the search completes.
 *
 * \param n The DHT node.
 * \param search_type Type of search. One of the \ref dht_search_type enum
                      values.
 * \param id The search target.
 * \param callback Function that will be called when the search completes.
 * \param opaque Opaque pointer that will be passed to the callback when the
                 search completes.
 * \param handle Pointer to a variable that will receive the search handle.
 * \returns 0 if the search sucessfully started, or -1 in case of failure.
 */
int dht_node_search(struct dht_node *n, const unsigned char id[20],
                    int search_type,
                    search_complete_t callback, void *opaque,
                    dht_search_t *handle);

/*!
 * Cancel a pending DHT search.
 *
 * Cancels a currently running search and frees up associated ressources. The
 * search completion callback will be called immediately with a NULL list of
 * nodes.
 *
 * \param n The DHT node.
 * \param handle Handle to the search to cancel.
 */
void dht_node_cancel(struct dht_node *n, dht_search_t handle);

/*!
 * Dump the node's routing table.
 *
 * Outputs the node's bucket list for debugging purpose.
 *
 * \param n The DHT node.
 */
void dht_node_dump_buckets(struct dht_node *n);

/*!
 * Send announce queries for an infohash.
 *
 * Sends DHT announce queries for the given infohash. If \a implied_port is
 * non-zero, them the \a port parameter will be ignored and the node's UDP port
 * is used instead as the peer port.
 * This function is only meant to be used with a list of nodes obtained as the
 * result of a \p GET_PEERS search. Only the 8 nodes of the \a nodes list
 * will be subject to the announce query. See \ref dht_announce_peer for a
 * higher level interface.
 *
 * \param n The DHT node.
 * \param info_hash the 160-bit infohash.
 * \param nodes List of nodes sorted by increasing distance to the target
 *              infohash, as returned by \ref dht_node_search.
 * \param implied_port 0 to use the \a port parameter, 1 to use the current
 *        node's UDP port number.
 * \param port Announced peer's port number if \a implied_port is 0, ignored
 *             otherwise.
 */
void dht_node_announce(struct dht_node *n, const unsigned char *info_hash,
                       const struct search_node *nodes,
                       int implied_port, int port);

/*!
 * Store immutable data in the DHT.
 *
 * Send a "put" query to the specified nodes with the given value \a val
 * to store as immutable data. Only the 8 first nodes of the \a nodes list
 * will be subject to the announce query. See \ref dht_put_immutable for a
 * higher level interface.
 *
 * \param n The DHT node.
 * \param nodes List of nodes sorted by increasing distance to the target
 *              hash, as returned by \ref dht_node_search.
 * \param val Value to be stored on the target nodes.
 */
void dht_node_put_immutable(struct dht_node *n,
                            const struct search_node *nodes,
                            const struct bvalue *val);

/*!
 * Store mutable data in the DHT.
 *
 * Send a "put" query to the specified nodes with the given value \a val
 * to store as mutable data. Only the 8 first nodes of the \a nodes list
 * will be subject to the put query. See \ref dht_put_mutable for a higher
 * level interface.
 *
 * \param n The DHT node.
 * \param nodes List of nodes sorted by increasing distance to the target
 *              hash, as returned by \ref dht_node_search.
 * \param k ed25519 public key used to authenticate the query.
 * \param signature ed25519 signature of the query.
 * \param salt Salt data added to compute the target hash.
 * \param salt_len Length of the salt data (max=64).
 * \param seq Sequence number.
 * \param val Value to be stored on the target nodes.
 */
void dht_node_put_mutable(struct dht_node *n,
                          const struct search_node *nodes,
                          const unsigned char k[32],
                          const unsigned char signature[64],
                          const unsigned char *salt, size_t salt_len,
                          int seq, const struct bvalue *val);

/*!
 * Save node state.
 *
 * Saves the state of a node into a dictionnary value ready to be serialized to
 * a file. This function saves the node ID an the content of the node's routing
 * table. This allows the node to be stopped and then restarted in a future
 * invocation of the same software without having to go through the bootstrap
 * process again.
 *
 * \param n The DHT node.
 * \returns The node's state as a dictionary value.
 */
struct bvalue *dht_node_save(const struct dht_node *n);

/*!
 * Restore node state.
 *
 * Restores the node to a previous state. The result of calling this function
 * after the node has already started with \ref dht_node_start is undefined.
 *
 * \param dict The state to restore as a dictionary value.
 * \param n The DHT node.
 * \returns 0 on success or -1 if \a dict is invalid (invalid version).
 */
int dht_node_restore(const struct bvalue *dict, struct dht_node *n);

/*!
 * Set bootstrap status notification callback.
 *
 * Register a callback that will be called when the node's bootstrap status
 * changes. It allows the user to be notified when the node is ready to issue
 * DHT searches.
 *
 * \param n The DHT node.
 * \param callback Bootstrap status callback.
 * \param opaque Opaque pointer that will be passed to the callback.
 * \returns bootstrap status.
 */
void dht_node_set_bootstrap_callback(struct dht_node *n,
                                     bootstrap_status_t callback,
                                     void *opaque);

#ifdef __cplusplus
}
#endif

#endif /* DHT_NODE_H_ */
