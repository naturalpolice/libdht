include(GNUInstallDirs)

set(PUBLIC_HEADERS_DIR ${CMAKE_SOURCE_DIR}/include)
set(PUBLIC_HEADERS ${PUBLIC_HEADERS_DIR}/dht/bencode.h
                   ${PUBLIC_HEADERS_DIR}/dht/node.h
                   ${PUBLIC_HEADERS_DIR}/dht/peers.h
                   ${PUBLIC_HEADERS_DIR}/dht/put.h
                   ${PUBLIC_HEADERS_DIR}/dht/utils.h)

add_library(dht bencode.c
                crc32c.c
                hexdump.c
                hmac.c
                hmac.h
                ip_counter.c
                ip_counter.h
                node.c
                node.h
                peers.c
                put.c
                random.c
                random.h
                sha1.c
                sha1.h
                time.c
                time.h
                utils.c
                ed25519/add_scalar.c
                ed25519/ed25519.h
                ed25519/fe.c ed25519/fe.h
                ed25519/fixedint.h
                ed25519/ge.c ed25519/ge.h
                ed25519/key_exchange.c
                ed25519/keypair.c
                ed25519/precomp_data.h
                ed25519/sc.c ed25519/sc.h
                ed25519/seed.c
                ed25519/sha512.c ed25519/sha512.h
                ed25519/sign.c
                ed25519/verify.c
                ${PUBLIC_HEADERS})

target_include_directories(dht PUBLIC ${PUBLIC_HEADERS_DIR})
if(CMAKE_COMPILER_IS_GNUCC)
    target_compile_options(dht PRIVATE -W -Wall)
endif()
target_link_libraries(dht)
target_compile_definitions(dht PRIVATE ED25519_NO_SEED)
target_compile_definitions(dht PRIVATE "$<$<CONFIG:DEBUG>:DHT_DEBUG>")

install(TARGETS dht
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dht)
