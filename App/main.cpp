#include <iostream>
#include <GCrypton/Aes.hpp>

int main() {
    std::cout << "Hello from MyProject!" << std::endl;
    
    // std::array<uint8_t, 16U> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    // GCrypton::Aes<GCrypton::AesType::AES_128> aes{};
    // auto expandedKeys = aes.CreateRoundKeys(key);
    // (void)expandedKeys;
    return 0;
}
