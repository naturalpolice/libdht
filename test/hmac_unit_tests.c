#include <stdlib.h>
#include <setjmp.h>
#include <stdarg.h>

#include <cmocka.h>

#include "../lib/hmac.h"

const char *hex(const unsigned char id[20]);
int from_hex(const char *s, unsigned char id[20]);


/*
 * From RFC2202:
 * 
 * 3. Test Cases for HMAC-SHA-1
 * 
 * test_case =     1
 * key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
 * key_len =       20
 * data =          "Hi There"
 * data_len =      8
 * digest =        0xb617318655057264e28bc0b6fb378c8ef146be00
 * 
 * test_case =     2
 * key =           "Jefe"
 * key_len =       4
 * data =          "what do ya want for nothing?"
 * data_len =      28
 * digest =        0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
 * 
 * test_case =     3
 * key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 * key_len =       20
 * data =          0xdd repeated 50 times
 * data_len =      50
 * digest =        0x125d7342b9ac11cd91a39af48aa17b4f63f175d3
 * 
 * test_case =     4
 * key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
 * key_len =       25
 * data =          0xcd repeated 50 times
 * data_len =      50
 * digest =        0x4c9007f4026250c6bc8414f9bf50c86c2d7235da
 * 
 * test_case =     5
 * key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
 * key_len =       20
 * data =          "Test With Truncation"
 * data_len =      20
 * digest =        0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
 * digest-96 =     0x4c1a03424b55e07fe7f27be1
 * 
 * test_case =     6
 * key =           0xaa repeated 80 times
 * key_len =       80
 * data =          "Test Using Larger Than Block-Size Key - Hash Key First"
 * data_len =      54
 * digest =        0xaa4ae5e15272d00e95705637ce8a3b55ed402112
 * 
 * test_case =     7
 * key =           0xaa repeated 80 times
 * key_len =       80
 * data =          "Test Using Larger Than Block-Size Key and Larger
 *                 Than One Block-Size Data"
 * data_len =      73
 * digest =        0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
 * data_len =      20
 * digest =        0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
 * digest-96 =     0x4c1a03424b55e07fe7f27be1
 * 
 * test_case =     6
 * key =           0xaa repeated 80 times
 * key_len =       80
 * data =          "Test Using Larger Than Block-Size Key - Hash Key
 * First"
 * data_len =      54
 * digest =        0xaa4ae5e15272d00e95705637ce8a3b55ed402112
 * 
 * test_case =     7
 * key =           0xaa repeated 80 times
 * key_len =       80
 * data =          "Test Using Larger Than Block-Size Key and Larger
 *                 Than One Block-Size Data"
 * data_len =      73
 * digest =        0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
 */


static void hmac_sha1_test1(void **state)
{
    struct hmac_context h;
    unsigned char tmp[20];

    from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", tmp);

    hmac_init(&h, tmp, 20);
    hmac_update(&h, "Hi There", 8);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("b617318655057264e28bc0b6fb378c8ef146be00", hex(tmp));
}

static void hmac_sha1_test2(void **state)
{
    struct hmac_context h;
    unsigned char tmp[20];

    hmac_init(&h, "Jefe", 4);
    hmac_update(&h, "what do ya want for nothing?", 28);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", hex(tmp));
}

static void hmac_sha1_test3(void **state)
{
    struct hmac_context h;
    unsigned char tmp[20];
    size_t i;
    unsigned char c;

    from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tmp);

    hmac_init(&h, tmp, 20);
    c = 0xdd;
    for (i = 0; i < 50; i++)
        hmac_update(&h, &c, 1);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("125d7342b9ac11cd91a39af48aa17b4f63f175d3", hex(tmp));
}

static void hmac_sha1_test4(void **state)
{
    struct hmac_context h;
    unsigned char tmp[20];
    size_t i;
    unsigned char c;

    hmac_init(&h, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25);
    c = 0xcd;
    for (i = 0; i < 50; i++)
        hmac_update(&h, &c, 1);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("4c9007f4026250c6bc8414f9bf50c86c2d7235da", hex(tmp));
}

static void hmac_sha1_test5(void **state)
{
    struct hmac_context h;
    unsigned char tmp[20];

    from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", tmp);

    hmac_init(&h, tmp, 20);
    hmac_update(&h, "Test With Truncation", 20);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", hex(tmp));
}

static void hmac_sha1_test6(void **state)
{
    struct hmac_context h;
    unsigned char tmp[80];
    size_t i;

    for (i = 0; i < 80; i++)
        tmp[i] = 0xaa;
        
    hmac_init(&h, tmp, 80);
    hmac_update(&h, "Test Using Larger Than Block-Size Key - Hash Key First",
                54);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("aa4ae5e15272d00e95705637ce8a3b55ed402112", hex(tmp));
}

static void hmac_sha1_test7(void **state)
{
    struct hmac_context h;
    unsigned char tmp[80];
    size_t i;

    for (i = 0; i < 80; i++)
        tmp[i] = 0xaa;
        
    hmac_init(&h, tmp, 80);
    hmac_update(&h, "Test Using Larger Than Block-Size Key and Larger "
                    "Than One Block-Size Data", 73);
    hmac_finish(&h, tmp);
    hmac_free(&h);

    assert_string_equal("e8e99d0f45237d786d6bbaa7965c7808bbff1a91", hex(tmp));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hmac_sha1_test1),
        cmocka_unit_test(hmac_sha1_test2),
        cmocka_unit_test(hmac_sha1_test3),
        cmocka_unit_test(hmac_sha1_test4),
        cmocka_unit_test(hmac_sha1_test5),
        cmocka_unit_test(hmac_sha1_test6),
        cmocka_unit_test(hmac_sha1_test7),
    };

    return cmocka_run_group_tests_name("hmac", tests, NULL, NULL);
}
