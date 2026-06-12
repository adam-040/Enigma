# Ghidra C++ Decompiler Library
# Builds the decompiler as a static library with namespace ghidra_decompiler

cmake_minimum_required(VERSION 3.16)

# Exclude standalone programs and BFD-dependent files
set(DECOMPILER_EXCLUDES
    consolemain.cc
    test.cc
    testfunction.cc
    sleighexample.cc
    bfd_arch.cc
    loadimage_bfd.cc
)

# Collect all .cc files
file(GLOB DECOMPILER_SOURCES "*.cc")

# Remove excluded files
foreach(exclude ${DECOMPILER_EXCLUDES})
    list(FILTER DECOMPILER_SOURCES EXCLUDE REGEX ".*${exclude}$")
endforeach()

# Create static library (use system zlib instead of incomplete local copy)
add_library(decompiler STATIC
    ${DECOMPILER_SOURCES}
)

target_include_directories(decompiler SYSTEM PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link system zlib
target_link_libraries(decompiler PUBLIC z)

# Define to disable BFD support
target_compile_definitions(decompiler PRIVATE NO_BFD)

# C++17 standard
target_compile_features(decompiler PUBLIC cxx_std_17)

# Suppress warnings for third-party code
if(MSVC)
    target_compile_options(decompiler PRIVATE /W0)
else()
    target_compile_options(decompiler PRIVATE -w)
endif()
