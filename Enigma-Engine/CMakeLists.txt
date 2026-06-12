cmake_minimum_required(VERSION 3.16)
project(enigma-engine VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MSYS2_MINGW64_ROOT "$ENV{MSYSTEM_PREFIX}" CACHE PATH "Optional MSYS2 MinGW64 prefix")
set(ENIGMA_SLEIGH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sleigh" CACHE PATH "Root directory for compiled SLEIGH specs")

find_path(CAPSTONE_INCLUDE_DIR NAMES capstone/capstone.h HINTS "$ENV{MSYSTEM_PREFIX}/include" "${MSYS2_MINGW64_ROOT}/include")
find_library(CAPSTONE_LIBRARY NAMES capstone libcapstone HINTS "$ENV{MSYSTEM_PREFIX}/lib" "${MSYS2_MINGW64_ROOT}/lib")

find_path(SQLITE3_INCLUDE_DIR NAMES sqlite3.h HINTS "$ENV{MSYSTEM_PREFIX}/include" "${MSYS2_MINGW64_ROOT}/include")
find_library(SQLITE3_LIBRARY NAMES sqlite3 libsqlite3 HINTS "$ENV{MSYSTEM_PREFIX}/lib" "${MSYS2_MINGW64_ROOT}/lib")

if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone was not found. Set CAPSTONE_INCLUDE_DIR/CAPSTONE_LIBRARY or MSYS2_MINGW64_ROOT.")
endif()
if(NOT SQLITE3_INCLUDE_DIR OR NOT SQLITE3_LIBRARY)
    message(FATAL_ERROR "SQLite3 was not found. Set SQLITE3_INCLUDE_DIR/SQLITE3_LIBRARY or MSYS2_MINGW64_ROOT.")
endif()

# LMDB
find_path(LMDB_INCLUDE_DIR NAMES lmdb.h HINTS "$ENV{MSYSTEM_PREFIX}/include" "${MSYS2_MINGW64_ROOT}/include")
find_library(LMDB_LIBRARY NAMES lmdb liblmdb HINTS "$ENV{MSYSTEM_PREFIX}/lib" "${MSYS2_MINGW64_ROOT}/lib")
if(NOT LMDB_INCLUDE_DIR OR NOT LMDB_LIBRARY)
    message(FATAL_ERROR "LMDB was not found. Set LMDB_INCLUDE_DIR/LMDB_LIBRARY or MSYS2_MINGW64_ROOT.")
endif()

# FlatBuffers
find_path(FLATBUFFERS_INCLUDE_DIR NAMES flatbuffers/flatbuffers.h HINTS "$ENV{MSYSTEM_PREFIX}/include" "${MSYS2_MINGW64_ROOT}/include")
find_library(FLATBUFFERS_LIBRARY NAMES flatbuffers libflatbuffers HINTS "$ENV{MSYSTEM_PREFIX}/lib" "${MSYS2_MINGW64_ROOT}/lib")
find_program(FLATC_EXECUTABLE NAMES flatc HINTS "$ENV{MSYSTEM_PREFIX}/bin" "${MSYS2_MINGW64_ROOT}/bin")
if(NOT FLATBUFFERS_INCLUDE_DIR OR NOT FLATBUFFERS_LIBRARY OR NOT FLATC_EXECUTABLE)
    message(FATAL_ERROR "FlatBuffers or flatc was not found.")
endif()

# FlatBuffers schema compilation
set(FBS_SCHEMAS
    ${CMAKE_CURRENT_SOURCE_DIR}/schemas/program.fbs
    ${CMAKE_CURRENT_SOURCE_DIR}/schemas/project.fbs
    ${CMAKE_CURRENT_SOURCE_DIR}/schemas/commit.fbs
    ${CMAKE_CURRENT_SOURCE_DIR}/schemas/changeset.fbs
)
set(FBS_OUTPUT_DIR ${CMAKE_BINARY_DIR}/schemas)
file(MAKE_DIRECTORY ${FBS_OUTPUT_DIR})

add_custom_command(
    OUTPUT
        ${FBS_OUTPUT_DIR}/program_generated.h
        ${FBS_OUTPUT_DIR}/project_generated.h
        ${FBS_OUTPUT_DIR}/commit_generated.h
        ${FBS_OUTPUT_DIR}/changeset_generated.h
    COMMAND ${FLATC_EXECUTABLE} --cpp -o ${FBS_OUTPUT_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/schemas/program.fbs
        ${CMAKE_CURRENT_SOURCE_DIR}/schemas/project.fbs
        ${CMAKE_CURRENT_SOURCE_DIR}/schemas/commit.fbs
        ${CMAKE_CURRENT_SOURCE_DIR}/schemas/changeset.fbs
    DEPENDS ${FBS_SCHEMAS}
    COMMENT "Compiling FlatBuffers schemas..."
)
add_custom_target(flatbuffers_schemas DEPENDS
    ${FBS_OUTPUT_DIR}/program_generated.h
    ${FBS_OUTPUT_DIR}/project_generated.h
    ${FBS_OUTPUT_DIR}/commit_generated.h
    ${FBS_OUTPUT_DIR}/changeset_generated.h
)

# enigma_engine Library
file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "src/include/ghidra/*.h")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/**/*.cpp")
file(GLOB_RECURSE DECOMPILER_SOURCES "src/decompiler/*.hh" "src/decompiler/*.cc")

add_library(decompiler STATIC ${DECOMPILER_SOURCES})
target_include_directories(decompiler PUBLIC ${CMAKE_SOURCE_DIR}/src/decompiler)
target_link_libraries(decompiler PRIVATE ${CAPSTONE_LIBRARY} z)

list(FILTER SOURCES EXCLUDE REGEX "/gui/")
add_library(enigma_engine ${SOURCES} ${HEADERS})
add_dependencies(enigma_engine flatbuffers_schemas)
target_include_directories(enigma_engine PUBLIC ${CMAKE_SOURCE_DIR}/src/include ${FBS_OUTPUT_DIR})
target_include_directories(enigma_engine PRIVATE ${CAPSTONE_INCLUDE_DIR} ${SQLITE3_INCLUDE_DIR} ${LMDB_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/src/decompiler)
target_link_libraries(enigma_engine PRIVATE ${CAPSTONE_LIBRARY} ${SQLITE3_LIBRARY} ${LMDB_LIBRARY} ${FLATBUFFERS_LIBRARY} decompiler)
target_compile_definitions(enigma_engine PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")

function(enigma_apply_warning_policy target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /wd4100 /wd4250)
    else()
        target_compile_options(${target_name} PRIVATE -Wno-unused-parameter -Wno-overloaded-virtual -Wno-reorder)
    endif()
endfunction()

# Qt6 GUI
find_package(Qt6 QUIET COMPONENTS Widgets Concurrent)
if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    file(GLOB_RECURSE GUI_SOURCES CONFIGURE_DEPENDS "src/gui/*.cpp")
    file(GLOB_RECURSE GUI_HEADERS CONFIGURE_DEPENDS "src/gui/*.h")
    add_executable(enigma_gui ${GUI_SOURCES} ${GUI_HEADERS} src/gui/resources.qrc)
    target_include_directories(enigma_gui PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
    target_link_libraries(enigma_gui PRIVATE enigma_engine Qt6::Widgets Qt6::Concurrent)
    target_compile_definitions(enigma_gui PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
    enigma_apply_warning_policy(enigma_gui)
    message(STATUS "Qt6 GUI enabled: enigma_gui")
else()
    message(STATUS "Qt6 not found — GUI target disabled")
endif()

enable_testing()

add_executable(enigma_test_compile tests/test_compile.cpp)
target_link_libraries(enigma_test_compile PRIVATE enigma_engine)
target_compile_definitions(enigma_test_compile PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_compile)
add_test(NAME enigma_test_compile COMMAND enigma_test_compile)

add_executable(enigma_test_decompiler tests/test_decompiler.cpp)
target_link_libraries(enigma_test_decompiler PRIVATE enigma_engine)
target_compile_definitions(enigma_test_decompiler PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_decompiler)
add_test(NAME enigma_test_decompiler COMMAND enigma_test_decompiler)

add_executable(enigma_test_decomp_interface tests/test_decomp_interface.cpp)
target_link_libraries(enigma_test_decomp_interface PRIVATE enigma_engine)
target_include_directories(enigma_test_decomp_interface PRIVATE ${FBS_OUTPUT_DIR})
target_compile_definitions(enigma_test_decomp_interface PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
add_dependencies(enigma_test_decomp_interface flatbuffers_schemas)
enigma_apply_warning_policy(enigma_test_decomp_interface)
add_test(NAME enigma_test_decomp_interface COMMAND enigma_test_decomp_interface)

add_executable(enigma_test_loader tests/test_loader.cpp)
target_link_libraries(enigma_test_loader PRIVATE enigma_engine)
target_compile_definitions(enigma_test_loader PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_loader)
add_test(NAME enigma_test_loader COMMAND enigma_test_loader)

add_executable(enigma_test_macho_loader tests/test_macho_loader.cpp)
target_link_libraries(enigma_test_macho_loader PRIVATE enigma_engine)
target_compile_definitions(enigma_test_macho_loader PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_macho_loader)
add_test(NAME enigma_test_macho_loader COMMAND enigma_test_macho_loader)

add_executable(enigma_test_headless_suite tests/test_headless_suite.cpp)
target_link_libraries(enigma_test_headless_suite PRIVATE enigma_engine)
target_compile_definitions(enigma_test_headless_suite PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_headless_suite)
add_test(NAME enigma_test_headless_suite COMMAND enigma_test_headless_suite)

add_executable(enigma_test_stress tests/test_decompiler_stress.cpp)
target_link_libraries(enigma_test_stress PRIVATE enigma_engine)
target_include_directories(enigma_test_stress SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/src/decompiler)
target_compile_definitions(enigma_test_stress PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_stress)
add_test(NAME enigma_test_stress COMMAND enigma_test_stress)

add_executable(enigma_test_pipeline tests/test_pipeline.cpp)
target_link_libraries(enigma_test_pipeline PRIVATE enigma_engine)
target_compile_definitions(enigma_test_pipeline PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_pipeline)
add_test(NAME enigma_test_pipeline COMMAND enigma_test_pipeline)

add_executable(enigma_test_pipeline_comprehensive tests/test_pipeline_comprehensive.cpp)
target_link_libraries(enigma_test_pipeline_comprehensive PRIVATE enigma_engine)
target_compile_definitions(enigma_test_pipeline_comprehensive PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_pipeline_comprehensive)
add_test(NAME enigma_test_pipeline_comprehensive COMMAND enigma_test_pipeline_comprehensive)

foreach(test_name enigma_test_block_struct enigma_test_lang_classes enigma_test_batch_e enigma_test_batch_f enigma_test_batch_g enigma_test_batch_h enigma_test_batch_i enigma_test_batch_j enigma_test_batch_k enigma_test_batch_l enigma_test_batch_n enigma_test_batch_o enigma_test_batch_p enigma_test_batch_q enigma_test_batch_r enigma_test_batch_s enigma_test_batch_t enigma_test_analyzer_integration enigma_test_batch_u enigma_test_batch_v enigma_test_batch_w enigma_test_batch_x enigma_test_batch_y enigma_test_batch_z enigma_test_batch_aa enigma_test_batch_ab)
    string(REPLACE "enigma_" "" file_base ${test_name})
    add_executable(${test_name} tests/${file_base}.cpp)
    target_link_libraries(${test_name} PRIVATE enigma_engine)
    target_compile_definitions(${test_name} PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
    enigma_apply_warning_policy(${test_name})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

add_executable(enigma_test_apply_known_signature tests/test_apply_known_signature.cpp)
target_link_libraries(enigma_test_apply_known_signature PRIVATE enigma_engine)
target_compile_definitions(enigma_test_apply_known_signature PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_test_apply_known_signature)
add_test(NAME enigma_test_apply_known_signature COMMAND enigma_test_apply_known_signature)

foreach(test_name enigma_test_signature_persistence enigma_test_repository_reload enigma_test_type_roundtrip enigma_test_gap_verification enigma_test_pdb_parser enigma_test_storage_p1 enigma_test_storage_p2 enigma_test_storage_p3 enigma_test_storage_p4 enigma_test_storage_p5)
    string(REPLACE "enigma_" "" file_base ${test_name})
    if(test_name MATCHES "enigma_test_storage_p[1-5]")
        string(REPLACE "p" "phase" file_base ${file_base})
    endif()
    add_executable(${test_name} tests/${file_base}.cpp)
    target_link_libraries(${test_name} PRIVATE enigma_engine)
    target_include_directories(${test_name} PRIVATE ${FBS_OUTPUT_DIR})
    target_compile_definitions(${test_name} PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
    add_dependencies(${test_name} flatbuffers_schemas)
    enigma_apply_warning_policy(${test_name})
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

add_executable(enigma_decompile tools/enigma_decompile.cpp)
target_link_libraries(enigma_decompile PRIVATE enigma_engine)
target_compile_definitions(enigma_decompile PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_decompile)

add_executable(enigma_decompile_full tools/enigma_decompile_full.cpp)
target_link_libraries(enigma_decompile_full PRIVATE enigma_engine)
target_include_directories(enigma_decompile_full SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/src/decompiler)
target_compile_definitions(enigma_decompile_full PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_decompile_full)

add_executable(enigma_binary_audit tools/enigma_binary_audit.cpp)
target_link_libraries(enigma_binary_audit PRIVATE enigma_engine)
target_include_directories(enigma_binary_audit SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/src/decompiler)
target_compile_definitions(enigma_binary_audit PRIVATE ENIGMA_SLEIGH_DIR="${ENIGMA_SLEIGH_DIR}")
enigma_apply_warning_policy(enigma_binary_audit)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME enigma_test_cli_regression COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_regression.py)
add_test(NAME enigma_test_corpus_regression COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_corpus_regression.py)
add_test(NAME enigma_test_determinism_regression COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_determinism_regression.py)
