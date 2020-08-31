find_package(CMocka REQUIRED)

add_executable(hmac_unit_tests hmac_unit_tests.c)
target_link_libraries(hmac_unit_tests dht cmocka)

add_executable(storage_unit_tests storage_unit_tests.c)
target_link_libraries(storage_unit_tests dht cmocka)

add_executable(api_tests_v4 api_tests.c)
target_compile_options(api_tests_v4 PRIVATE -W -Wall)
target_compile_definitions(api_tests_v4 PRIVATE TEST_NAME_SUFFIX=\"_v4\" IP_VERSION=4)
target_link_libraries(api_tests_v4 dht cmocka)

add_executable(api_tests_v6 api_tests.c)
target_compile_options(api_tests_v6 PRIVATE -W -Wall)
target_compile_definitions(api_tests_v6 PRIVATE TEST_NAME_SUFFIX=\"_v6\" IP_VERSION=6)
target_link_libraries(api_tests_v6 dht cmocka)
