#pragma once

namespace GCrypton {

template <AesType type>
consteval size_t Aes<type>::CALCULATE_NUM_OF_ROUND()
{
    switch (type)
    {
        case AesType::AES_128: return 10U;
        case AesType::AES_192: return 12U;
        case AesType::AES_256: return 14U;
    }
}

template <AesType type>
consteval std::array<std::uint32_t, Aes<type>::NUM_OF_ROUNDS> Aes<type>::CALCULATE_R_CON()
{
    std::array<std::uint32_t, NUM_OF_ROUNDS> roundConstants{};
    roundConstants[0U] = 1U << 24U;
    for (size_t i = 1U; i < NUM_OF_ROUNDS; i++)
    {
        uint8_t prevMSB = roundConstants[i - 1] >> 24U;
        uint8_t newMSB = prevMSB << 1U;
        if (prevMSB & 0x80U)
        {
            newMSB ^= 0x1BU;
        }
        roundConstants[i] = static_cast<uint32_t>(newMSB) << 24U;
    }
    return roundConstants;
}

template <AesType type>
typename Aes<type>::State Aes<type>::CreateState(std::span<uint8_t, 16U> data)
{
    State state{};
    std::memcpy(state.data(), data.data(), data.size());
    return state;
}

template <AesType type>
std::array<std::uint8_t, 16U> Aes<type>::CreateOutputArray(const State& state)
{
    std::array<std::uint8_t, 16U> output{};
    std::memcpy(output.data(), state.data(), output.size());
    return output;
}

template <AesType type>
typename Aes<type>::State& Aes<type>::AddRoundKey(State& state, std::span<std::uint32_t, 4U> roundKey)
{
    for (size_t i = 0U; i < state.size(); i++)
    {
        state[i] ^= roundKey[i];
    }
    return state;
}

template <AesType type>
typename Aes<type>::State& Aes<type>::SubBytes(State& state)
{
    std::ranges::for_each(state, [this](uint32_t& word) {
        word = SubWord(word);
    });
    return state;
}

template <AesType type>
std::uint32_t Aes<type>::SubWord(std::uint32_t word)
{
    uint32_t result = 0;
    for (size_t i = 0; i < 4; ++i)
    {
        uint8_t byte = (word >> (24 - 8 * i)) & 0xFF;
        result |= static_cast<uint32_t>(S_box[byte]) << (24 - 8 * i);
    }
    return result;
}

template <AesType type>
typename Aes<type>::ExpandedKeyType Aes<type>::CreateRoundKeys(KeyType key)
{
    ExpandedKeyType roundKeys{};
    uint32_t temp = 0U;
    size_t i = 0U;
    for (; i < KEY_WORDS_COUNT; i++)
    {
        const size_t keyOffset = 4U * i;
        roundKeys[i] = key[keyOffset + 0U] << 24U |
                       key[keyOffset + 1U] << 16U |
                       key[keyOffset + 2U] << 8U |
                       key[keyOffset + 3U];
    }
    while (i < roundKeys.size())
    {
        temp = roundKeys[i - 1];
        if (i % KEY_WORDS_COUNT == 0)
        {
            temp = SubWord(std::rotl(temp, 8U)) ^ R_CON[(i - 1) / KEY_WORDS_COUNT];
        }
        else if (KEY_WORDS_COUNT > 6U && i % KEY_WORDS_COUNT == 4U)
        {
            temp = SubWord(temp);
        }
        roundKeys[i] = roundKeys[i - KEY_WORDS_COUNT] ^ temp;
        i++;
    }

    return roundKeys;
}

template <AesType type>
std::array<std::uint8_t, 16U> Aes<type>::Encrypt(std::span<uint8_t, 16U> data, KeyType key)
{
    auto roundKeys = CreateRoundKeys(key);
    auto state = CreateState(data);
    state = AddRoundKey(state, roundKeys[0U]);
    state = SubBytes(state);
    return CreateOutputArray(state);
}

} 