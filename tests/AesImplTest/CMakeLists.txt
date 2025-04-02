project(GCryptonAesImplTests)

find_package(Catch2 3 REQUIRED)

# Add test executable
add_executable(GCryptonAesImpl_tests
    AesImplTests.cpp
)

add_definitions( -DCATCH_CONFIG_MAIN )

# Link against our library and Catch2
target_link_libraries(GCryptonAesImpl_tests
    PRIVATE
        GCrypton
        Catch2::Catch2WithMain
)

# Register tests with CTest
include(CTest)
add_test(NAME GCryptonAesImpl COMMAND GCryptonAesImpl_tests)
