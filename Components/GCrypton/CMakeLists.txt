add_library(GCrypton INTERFACE)

target_include_directories(GCrypton
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tpp
)

