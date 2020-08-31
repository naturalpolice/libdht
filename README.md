libdht
======

`libdht` is a C implementation of the Kademlia-based Distributed Hash Table
(DHT) used in the BitTorrent network (aka "mainline DHT").

Features
--------

* Full DHT node implementation.
* Search peers for an infohash. Announce as peer for an infohash.
  [BEP-5](https://www.bittorrent.org/beps/bep_0005.html)
* Save/Restore node state and routing table.
* Support for DHT Security Extension (node ID hardening).
  [BEP-42](https://www.bittorrent.org/beps/bep_0042.html)
* Immutable and mutable arbitrary data storage.
  [BEP-44](https://www.bittorrent.org/beps/bep_0044.html)
* IPv6 support. [BEP-32](https://www.bittorrent.org/beps/bep_0032.html)
* Does not depend on any external component/library.
* Independent from the network API, can be used in an event-driven or blocking
  fashion.
* Lua bindings

License
-------

libdht is distributed under the MIT license (see LICENSE). The present source
also incorporates code from the following external projects:

* Ed25519 implementation based on SUPERCOP "ref10"
  (https://github.com/orlp/ed25519). zlib licence.
* SHA1 implementation from Mbed TLS (https://tls.mbed.org). Apache 2.0 license.
* CRC32C (cagtagnoli) implementation based on Intel's Slicing-by-8 sourceforge
  project (https://sourceforge.net/projects/slicing-by-8/). BSD license.

Dependencies
------------

libdht only depends on the following libraries:

* cmocka: Needed for building the unit tests (optional).
* lua: Needed for building the lua bindings (optional).

It does not require any other external libraries.

Supported platforms
-------------------

So far libdht has been successfully built and tested on:

* Ubuntu Linux (16.04+)
* Windows 10 (MSVC/Visual Studio Build Tools 2017)

Running a DHT node
------------------

Here is an example to get started operating a basic DHT node. Please refer to
the rest of the documentation for more complex scenarios.

    #include <stdlib.h>
    #include <stdio.h>
    #include <errno.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <netinet/in.h>

    #include <dht/node.h>

    static void sock_send(const unsigned char *data, size_t len,
                          const struct sockaddr *dest, socklen_t addrlen,
                          void *opaque)
    {
        int sock = *(int *)opaque;

        if (sendto(sock, data, len, 0, dest, addrlen) < 0)
            fprintf(stderr, "sendto: %s\n", strerror(errno));
    }

    int node_run(void)
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sin;
        struct dht_node node;

        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_port = htons(6881);

        bind(sock, (struct sockaddr *)&sin, sizeof(sin));

        if (dht_node_init(&node, NULL, sock_send, &sock))
            return -1;

        dht_node_start(&node);

        while (1) {
            struct timeval tv;
            fd_set rfds;
            int rc;

            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);

            dht_node_timeout(&node, &tv);
            rc = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (rc < 0) {
                fprintf(stderr, "select: %s\n", strerror(errno));
                return -1;
            }
            if (rc && FD_ISSET(sock, &rfds)) {
                unsigned char buf[2048];
                struct sockaddr_storage ss;
                socklen_t sl = sizeof(ss);

                rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
                if (rc < 0) {
                    fprintf(stderr, "recvfrom: %s\n", strerror(errno));
                    return -1;
                }

                dht_node_input(&node, buf, rc, (struct sockaddr *)&ss, sl);
            }

            dht_node_work(&node);
        }

        return 0;
    }
