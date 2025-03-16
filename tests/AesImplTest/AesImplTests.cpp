#include <catch2/catch.hpp>
#include <GCrypton/Aes.hpp>

TEST_CASE("Aes implementation test", "[AES_IMPL]") 
{
    SECTION("Key extention algorithm") 
    {
        std::array<uint8_t, 16U> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        GCrypton::Aes<GCrypton::AesType::AES_128> aes{};
        auto expandedKeys = aes.CreateRoundKeys(key);

        // Round 0 (Original key)
        REQUIRE(expandedKeys[0] == 0x2b7e1516);  // w[0]
        REQUIRE(expandedKeys[1] == 0x28aed2a6);  // w[1]
        REQUIRE(expandedKeys[2] == 0xabf71588);  // w[2]
        REQUIRE(expandedKeys[3] == 0x09cf4f3c);  // w[3]
        
        // Round 1
        REQUIRE(expandedKeys[4] == 0xa0fafe17);  // w[4]
        REQUIRE(expandedKeys[5] == 0x88542cb1);  // w[5]
        REQUIRE(expandedKeys[6] == 0x23a33939);  // w[6]
        REQUIRE(expandedKeys[7] == 0x2a6c7605);  // w[7]
        
        // Round 2
        REQUIRE(expandedKeys[8] == 0xf2c295f2);  // w[8]
        REQUIRE(expandedKeys[9] == 0x7a96b943);  // w[9]
        REQUIRE(expandedKeys[10] == 0x5935807a);  // w[10]
        REQUIRE(expandedKeys[11] == 0x7359f67f);  // w[11]
        
        // Round 3
        REQUIRE(expandedKeys[12] == 0x3d80477d);  // w[12]
        REQUIRE(expandedKeys[13] == 0x4716fe3e);  // w[13]
        REQUIRE(expandedKeys[14] == 0x1e237e44);  // w[14]
        REQUIRE(expandedKeys[15] == 0x6d7a883b);  // w[15]
        
        // Round 4
        REQUIRE(expandedKeys[16] == 0xef44a541);  // w[16]
        REQUIRE(expandedKeys[17] == 0xa8525b7f);  // w[17]
        REQUIRE(expandedKeys[18] == 0xb671253b);  // w[18]
        REQUIRE(expandedKeys[19] == 0xdb0bad00);  // w[19]
        
        // Round 5
        REQUIRE(expandedKeys[20] == 0xd4d1c6f8);  // w[20]
        REQUIRE(expandedKeys[21] == 0x7c839d87);  // w[21]
        REQUIRE(expandedKeys[22] == 0xcaf2b8bc);  // w[22]
        REQUIRE(expandedKeys[23] == 0x11f915bc);  // w[23]
        
        // Round 6
        REQUIRE(expandedKeys[24] == 0x6d88a37a);  // w[24]
        REQUIRE(expandedKeys[25] == 0x110b3efd);  // w[25]
        REQUIRE(expandedKeys[26] == 0xdbf98641);  // w[26]
        REQUIRE(expandedKeys[27] == 0xca0093fd);  // w[27]
        
        // Round 7
        REQUIRE(expandedKeys[28] == 0x4e54f70e);  // w[28]
        REQUIRE(expandedKeys[29] == 0x5f5fc9f3);  // w[29]
        REQUIRE(expandedKeys[30] == 0x84a64fb2);  // w[30]
        REQUIRE(expandedKeys[31] == 0x4ea6dc4f);  // w[31]
        
        // Round 8
        REQUIRE(expandedKeys[32] == 0xead27321);  // w[32]
        REQUIRE(expandedKeys[33] == 0xb58dbad2);  // w[33]
        REQUIRE(expandedKeys[34] == 0x312bf560);  // w[34]
        REQUIRE(expandedKeys[35] == 0x7f8d292f);  // w[35]
        
        // Round 9
        REQUIRE(expandedKeys[36] == 0xac7766f3);  // w[36]
        REQUIRE(expandedKeys[37] == 0x19fadc21);  // w[37]
        REQUIRE(expandedKeys[38] == 0x28d12941);  // w[38]
        REQUIRE(expandedKeys[39] == 0x575c006e);  // w[39]
        
        // Round 10
        REQUIRE(expandedKeys[40] == 0xd014f9a8);  // w[40]
        REQUIRE(expandedKeys[41] == 0xc9ee2589);  // w[41]
        REQUIRE(expandedKeys[42] == 0xe13f0cc8);  // w[42]
        REQUIRE(expandedKeys[43] == 0xb6630ca6);  // w[43]
    }
}
