# Common project settings

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build" FORCE)
endif()

# Enable compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O0 -ggdb -Wall -Wextra -Wpedantic -Werror)
elseif(MSVC)
    add_compile_options(/W4)
endif()

# Enable position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add address sanitizer option
option(USE_SANITIZER "Use address sanitizer" OFF)
if(USE_SANITIZER AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

# Export compile commands for tools like clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
