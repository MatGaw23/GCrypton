#pragma once

#include <algorithm>
#include <bit>
#include <cstring>
#include <span>

namespace GCrypton {

enum class AesType: std::size_t
{
    AES_128 = 128U,
    AES_192 = 192U,
    AES_256 = 256U
};

template <AesType type>
class Aes
{
public:
    static constexpr std::size_t KEY_BYTES_COUNT = static_cast<std::size_t>(type) / 8U;
    static constexpr std::size_t KEY_WORDS_COUNT = KEY_BYTES_COUNT / 4U;
    using KeyType = std::span<uint8_t, KEY_BYTES_COUNT>;
    using State = std::array<uint32_t, 4U>;
     
    std::array<std::uint8_t, 16U> Enrypt(std::span<uint8_t, 16U> data, KeyType key)
    {
        auto roundKeys = CreateRoundKeys(key);
        auto state = CreateState(data);

        state = AddRoundKey(state, std::span<uint32_t, 4U>(roundKeys[0U], 4U));
        state = SubBytes(state);
        
        return CreateOutputArray(state);
    }

// private:
    static constexpr std::array<std::uint8_t, 256U> S_box 
    {
        0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
        0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
        0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
        0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
        0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
        0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
        0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
        0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
        0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
        0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
        0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
        0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
        0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
        0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
        0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
        0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
    };

    State CreateState(std::span<uint8_t, 16U> data)
    {
        State state{};
        memcpy(state.data(), data.data(), data.size());
        return state;
    }

    std::array<std::uint8_t, 16U> CreateOutputArray(const State& state)
    {
        std::array<std::uint8_t, 16U> output{};

        std::memcpy(output.data(), state.data(), output.size());

        return output;
    }

    static consteval size_t CALCULATE_NUM_OF_ROUND()
    {
        switch(type)
        {
            case AesType::AES_128: 
                return 10U;
            case AesType::AES_192:
                return 12U;
            case AesType::AES_256:
                return 14U;
        }
    }
    static constexpr size_t NUM_OF_ROUNDS = CALCULATE_NUM_OF_ROUND();

    static consteval std::array<std::uint32_t, NUM_OF_ROUNDS> CALCULATE_R_CON()
    {
        std::array<std::uint32_t, NUM_OF_ROUNDS> roundConstants{};
        roundConstants[0U] = 1U  << 24;
        for (size_t i = 1U; i < NUM_OF_ROUNDS; i++)
        {
            size_t roundConstantMSB = 2 * (roundConstants[i - 1] >> 24U);

            if (roundConstantMSB > 0x80U)
            {
                roundConstantMSB ^= 0x11BU;
            }

            roundConstants[i] = roundConstantMSB << 24U;
        }

        return roundConstants;
    }
    static constexpr std::array<std::uint32_t, NUM_OF_ROUNDS> R_CON = CALCULATE_R_CON();
    
    using ExpandedKeyType = std::array<std::uint32_t, 4U * (NUM_OF_ROUNDS + 1U)>;
    
    ExpandedKeyType CreateRoundKeys(KeyType key)
    { 
        ExpandedKeyType roundKeys{};

        uint32_t temp = 0U;

        size_t i = 0U;
        for(; i < KEY_WORDS_COUNT; i++)
        {
            const size_t keyOffset = 4U * i;
            roundKeys[i] = key[keyOffset + 0U] << 24U |
                           key[keyOffset + 1U] << 16U |
                           key[keyOffset + 2U] << 8U  |
                           key[keyOffset + 3U];
        }

        while (i < roundKeys.size())
        {
            temp = roundKeys[i - 1];
            if (i % KEY_WORDS_COUNT == 0)
            {
                auto AfterRotWord = std::rotl(temp, 8U);
                auto AfterSubWord = SubWord(AfterRotWord);
                auto rcon_mytest = R_CON[(i - 1)/ KEY_WORDS_COUNT];

                auto Afterxor = AfterSubWord xor rcon_mytest;
                ;

                temp = Afterxor;
            }
            else if (KEY_WORDS_COUNT > 6U && i % KEY_WORDS_COUNT == 4U)
            {
                temp = SubWord(temp);
            }

            roundKeys[i] = roundKeys[i - KEY_WORDS_COUNT] xor temp;
            i++;
        }

        return roundKeys;
    }

    State& AddRoundKey(State& state, std::span<std::uint32_t, 4U> roundKey)
    {
        std::ranges::transform(state, roundKey, [](uint32_t& stateWord, uint32_t& key){
            stateWord ^= key;
        });

        return state;
    }

    State& SubBytes(State& state) 
    {
        std::ranges::for_each(state, [](uint32_t& word){
            word = SubWord(word);
        });
    
        return state;
    }

    std::uint32_t SubWord(std::uint32_t word)
    {
        auto bytes = reinterpret_cast<uint8_t*>(&word);

        for (size_t i = 0U; i < sizeof(word); i++)
        {
            *bytes = S_box[*bytes];
            bytes++;
        }

        return word;
    }
};

}
