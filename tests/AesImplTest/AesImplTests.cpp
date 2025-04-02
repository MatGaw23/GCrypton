#include <catch2/catch.hpp>
#include <GCrypton/Aes.hpp>

///  AES Key Expansion Test Cases  
///  This file contains test vectors derived from:
///  NIST FIPS 197 - "Advanced Encryption Standard (AES)"
///  Publication Date: November 26, 2001
///  
///  Test vectors are taken from:
///  - Appendix A.1: AES-128 Key Expansion Example
///  - Appendix A.2: AES-192 Key Expansion Example
///  - Appendix A.3: AES-256 Key Expansion Example
///  
/// Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
TEST_CASE("Aes implementation - Key Expansion", "[AES_IMPL_KEY_EXPANSION]") 
{
    SECTION("AES_126") 
    {
        std::array<uint8_t, 16U> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        GCrypton::Aes<GCrypton::AesType::AES_128> aes{};
        auto expandedKeys = aes.CreateRoundKeys(key);

        // Round 0 (Original key)
        REQUIRE(expandedKeys[0] == 0x2b7e1516);  
        REQUIRE(expandedKeys[1] == 0x28aed2a6);  
        REQUIRE(expandedKeys[2] == 0xabf71588);  
        REQUIRE(expandedKeys[3] == 0x09cf4f3c);  
        
        // Round 1
        REQUIRE(expandedKeys[4] == 0xa0fafe17);  
        REQUIRE(expandedKeys[5] == 0x88542cb1);  
        REQUIRE(expandedKeys[6] == 0x23a33939);  
        REQUIRE(expandedKeys[7] == 0x2a6c7605);  
        
        // Round 2
        REQUIRE(expandedKeys[8] == 0xf2c295f2);  
        REQUIRE(expandedKeys[9] == 0x7a96b943);  
        REQUIRE(expandedKeys[10] == 0x5935807a);  
        REQUIRE(expandedKeys[11] == 0x7359f67f);  
        
        // Round 3
        REQUIRE(expandedKeys[12] == 0x3d80477d);  
        REQUIRE(expandedKeys[13] == 0x4716fe3e);  
        REQUIRE(expandedKeys[14] == 0x1e237e44);  
        REQUIRE(expandedKeys[15] == 0x6d7a883b);  
        
        // Round 4
        REQUIRE(expandedKeys[16] == 0xef44a541);  
        REQUIRE(expandedKeys[17] == 0xa8525b7f);  
        REQUIRE(expandedKeys[18] == 0xb671253b);  
        REQUIRE(expandedKeys[19] == 0xdb0bad00);  
        
        // Round 5
        REQUIRE(expandedKeys[20] == 0xd4d1c6f8);  
        REQUIRE(expandedKeys[21] == 0x7c839d87);  
        REQUIRE(expandedKeys[22] == 0xcaf2b8bc);  
        REQUIRE(expandedKeys[23] == 0x11f915bc);  
        
        // Round 6
        REQUIRE(expandedKeys[24] == 0x6d88a37a);  
        REQUIRE(expandedKeys[25] == 0x110b3efd);  
        REQUIRE(expandedKeys[26] == 0xdbf98641);  
        REQUIRE(expandedKeys[27] == 0xca0093fd);  
        
        // Round 7
        REQUIRE(expandedKeys[28] == 0x4e54f70e);  
        REQUIRE(expandedKeys[29] == 0x5f5fc9f3);  
        REQUIRE(expandedKeys[30] == 0x84a64fb2);  
        REQUIRE(expandedKeys[31] == 0x4ea6dc4f);  
        
        // Round 8
        REQUIRE(expandedKeys[32] == 0xead27321);  
        REQUIRE(expandedKeys[33] == 0xb58dbad2);  
        REQUIRE(expandedKeys[34] == 0x312bf560);  
        REQUIRE(expandedKeys[35] == 0x7f8d292f);  
        
        // Round 9
        REQUIRE(expandedKeys[36] == 0xac7766f3);  
        REQUIRE(expandedKeys[37] == 0x19fadc21);  
        REQUIRE(expandedKeys[38] == 0x28d12941);  
        REQUIRE(expandedKeys[39] == 0x575c006e);  
        
        // Round 10
        REQUIRE(expandedKeys[40] == 0xd014f9a8);  
        REQUIRE(expandedKeys[41] == 0xc9ee2589);  
        REQUIRE(expandedKeys[42] == 0xe13f0cc8);  
        REQUIRE(expandedKeys[43] == 0xb6630ca6);  
    }

    SECTION("AES_192") 
    {
        std::array<uint8_t, 24U> key = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                                        0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
        GCrypton::Aes<GCrypton::AesType::AES_192> aes{};
        auto expandedKeys = aes.CreateRoundKeys(key);

        // Round 0 (Original key)
        REQUIRE(expandedKeys[0] == 0x8e73b0f7);  
        REQUIRE(expandedKeys[1] == 0xda0e6452);  
        REQUIRE(expandedKeys[2] == 0xc810f32b);  
        REQUIRE(expandedKeys[3] == 0x809079e5);  

        
        // Round 1
        REQUIRE(expandedKeys[4] == 0x62f8ead2);  
        REQUIRE(expandedKeys[5] == 0x522c6b7b);  
        REQUIRE(expandedKeys[6] == 0xfe0c91f7);  
        REQUIRE(expandedKeys[7] == 0x2402f5a5);  

        // Round 2
        REQUIRE(expandedKeys[8] == 0xec12068e);  
        REQUIRE(expandedKeys[9] == 0x6c827f6b);  
        REQUIRE(expandedKeys[10] == 0x0e7a95b9);  
        REQUIRE(expandedKeys[11] == 0x5c56fec2);  
        
        // Round 3
        REQUIRE(expandedKeys[12] == 0x4db7b4bd);  
        REQUIRE(expandedKeys[13] == 0x69b54118);  
        REQUIRE(expandedKeys[14] == 0x85a74796);  
        REQUIRE(expandedKeys[15] == 0xe92538fd);  

        // Round 4
        REQUIRE(expandedKeys[16] == 0xe75fad44);  
        REQUIRE(expandedKeys[17] == 0xbb095386);  
        REQUIRE(expandedKeys[18] == 0x485af057);  
        REQUIRE(expandedKeys[19] == 0x21efb14f);  
        
        // Round 5
        REQUIRE(expandedKeys[20] == 0xa448f6d9);  
        REQUIRE(expandedKeys[21] == 0x4d6dce24);  
        REQUIRE(expandedKeys[22] == 0xaa326360);  
        REQUIRE(expandedKeys[23] == 0x113b30e6);  
        
        // Round 6
        REQUIRE(expandedKeys[24] == 0xa25e7ed5);  
        REQUIRE(expandedKeys[25] == 0x83b1cf9a);  
        REQUIRE(expandedKeys[26] == 0x27f93943);  
        REQUIRE(expandedKeys[27] == 0x6a94f767);  
        
        // Round 7
        REQUIRE(expandedKeys[28] == 0xc0a69407);  
        REQUIRE(expandedKeys[29] == 0xd19da4e1);  
        REQUIRE(expandedKeys[30] == 0xec1786eb);  
        REQUIRE(expandedKeys[31] == 0x6fa64971);  
        
        // Round 8
        REQUIRE(expandedKeys[32] == 0x485f7032);  
        REQUIRE(expandedKeys[33] == 0x22cb8755);  
        REQUIRE(expandedKeys[34] == 0xe26d1352);  
        REQUIRE(expandedKeys[35] == 0x33f0b7b3);  
        
        // Round 9
        REQUIRE(expandedKeys[36] == 0x40beeb28);  
        REQUIRE(expandedKeys[37] == 0x2f18a259);  
        REQUIRE(expandedKeys[38] == 0x6747d26b);  
        REQUIRE(expandedKeys[39] == 0x458c553e);  
        
        // Round 10
        REQUIRE(expandedKeys[40] == 0xa7e1466c);  
        REQUIRE(expandedKeys[41] == 0x9411f1df);  
        REQUIRE(expandedKeys[42] == 0x821f750a);  
        REQUIRE(expandedKeys[43] == 0xad07d753);  
        
        // Round 11
        REQUIRE(expandedKeys[44] == 0xca400538);  
        REQUIRE(expandedKeys[45] == 0x8fcc5006);  
        REQUIRE(expandedKeys[46] == 0x282d166a);  
        REQUIRE(expandedKeys[47] == 0xbc3ce7b5);  
        
        // Round 12
        REQUIRE(expandedKeys[48] == 0xe98ba06f);  
        REQUIRE(expandedKeys[49] == 0x448c773c);  
        REQUIRE(expandedKeys[50] == 0x8ecc7204);  
        REQUIRE(expandedKeys[51] == 0x01002202);  
    }

    SECTION("AES_256")
    {
        std::array<uint8_t, 32U> key = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
        };
        
        GCrypton::Aes<GCrypton::AesType::AES_256> aes{};
        auto expandedKeys = aes.CreateRoundKeys(key);
        
        // Round 0 (Initial round key)
        REQUIRE(expandedKeys[0] == 0x603deb10);  
        REQUIRE(expandedKeys[1] == 0x15ca71be);  
        REQUIRE(expandedKeys[2] == 0x2b73aef0);  
        REQUIRE(expandedKeys[3] == 0x857d7781);  
        
        // Round 1 
        REQUIRE(expandedKeys[4] == 0x1f352c07);  
        REQUIRE(expandedKeys[5] == 0x3b6108d7);  
        REQUIRE(expandedKeys[6] == 0x2d9810a3);  
        REQUIRE(expandedKeys[7] == 0x0914dff4);  
        
        // Round 2
        REQUIRE(expandedKeys[8] == 0x9ba35411);  
        REQUIRE(expandedKeys[9] == 0x8e6925af);  
        REQUIRE(expandedKeys[10] == 0xa51a8b5f);  
        REQUIRE(expandedKeys[11] == 0x2067fcde);  
        
        // Round 3
        REQUIRE(expandedKeys[12] == 0xa8b09c1a);  
        REQUIRE(expandedKeys[13] == 0x93d194cd);  
        REQUIRE(expandedKeys[14] == 0xbe49846e);  
        REQUIRE(expandedKeys[15] == 0xb75d5b9a);  
        
        // Round 4
        REQUIRE(expandedKeys[16] == 0xd59aecb8);  
        REQUIRE(expandedKeys[17] == 0x5bf3c917);  
        REQUIRE(expandedKeys[18] == 0xfee94248);  
        REQUIRE(expandedKeys[19] == 0xde8ebe96);  
        
        // Round 5
        REQUIRE(expandedKeys[20] == 0xb5a9328a);  
        REQUIRE(expandedKeys[21] == 0x2678a647);  
        REQUIRE(expandedKeys[22] == 0x98312229);  
        REQUIRE(expandedKeys[23] == 0x2f6c79b3);  
        
        // Round 6
        REQUIRE(expandedKeys[24] == 0x812c81ad);  
        REQUIRE(expandedKeys[25] == 0xdadf48ba);  
        REQUIRE(expandedKeys[26] == 0x24360af2);  
        REQUIRE(expandedKeys[27] == 0xfab8b464);  
        
        // Round 7
        REQUIRE(expandedKeys[28] == 0x98c5bfc9);  
        REQUIRE(expandedKeys[29] == 0xbebd198e);  
        REQUIRE(expandedKeys[30] == 0x268c3ba7);  
        REQUIRE(expandedKeys[31] == 0x09e04214);  
        
        // Round 8
        REQUIRE(expandedKeys[32] == 0x68007bac);  
        REQUIRE(expandedKeys[33] == 0xb2df3316);  
        REQUIRE(expandedKeys[34] == 0x96e939e4);  
        REQUIRE(expandedKeys[35] == 0x6c518d80);  
        
        // Round 9
        REQUIRE(expandedKeys[36] == 0xc814e204);  
        REQUIRE(expandedKeys[37] == 0x76a9fb8a);  
        REQUIRE(expandedKeys[38] == 0x5025c02d);  
        REQUIRE(expandedKeys[39] == 0x59c58239);  
        
        // Round 10
        REQUIRE(expandedKeys[40] == 0xde136967);  
        REQUIRE(expandedKeys[41] == 0x6ccc5a71);  
        REQUIRE(expandedKeys[42] == 0xfa256395);  
        REQUIRE(expandedKeys[43] == 0x9674ee15);  
        
        // Round 11
        REQUIRE(expandedKeys[44] == 0x5886ca5d);  
        REQUIRE(expandedKeys[45] == 0x2e2f31d7);  
        REQUIRE(expandedKeys[46] == 0x7e0af1fa);  
        REQUIRE(expandedKeys[47] == 0x27cf73c3);  
        
        // Round 12
        REQUIRE(expandedKeys[48] == 0x749c47ab);  
        REQUIRE(expandedKeys[49] == 0x18501dda);  
        REQUIRE(expandedKeys[50] == 0xe2757e4f);  
        REQUIRE(expandedKeys[51] == 0x7401905a);  
        
        // Round 13
        REQUIRE(expandedKeys[52] == 0xcafaaae3);  
        REQUIRE(expandedKeys[53] == 0xe4d59b34);  
        REQUIRE(expandedKeys[54] == 0x9adf6ace);  
        REQUIRE(expandedKeys[55] == 0xbd10190d);  
        
        // Round 14
        REQUIRE(expandedKeys[56] == 0xfe4890d1);  
        REQUIRE(expandedKeys[57] == 0xe6188d0b);  
        REQUIRE(expandedKeys[58] == 0x046df344);  
        REQUIRE(expandedKeys[59] == 0x706c631e);  
    }
}

