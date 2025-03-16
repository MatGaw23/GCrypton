cmake_minimum_required(VERSION 3.14)
project(GCrypton VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectSettings)

# Options
option(BUILD_TESTS "Build the tests" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

# Add source code
add_subdirectory(src)

# Testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation rules
install(TARGETS GCrypton
        EXPORT GCryptonTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(DIRECTORY src/GCrypton/include/
        DESTINATION include)

# Generate and install export targets
install(EXPORT GCryptonTargets
        FILE GCryptonTargets.cmake
        NAMESPACE GCrypton::
        DESTINATION lib/cmake/GCrypton)
