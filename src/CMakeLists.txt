# Add the library
add_library(GCrypton INTERFACE)

# Set include directories
target_include_directories(GCrypton
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/GCrypton/include>
        $<INSTALL_INTERFACE:include>
)

# Add executable
add_executable(GCryptonApp main.cpp)
target_link_libraries(GCryptonApp PRIVATE GCrypton)
