cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(arch_sparc)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	arch_sparc.cpp
	# assembler.cpp
	disassembler.cpp
	# il.cpp
	util.cpp
	*.h
)

if(DEMO)
	add_library(arch_sparc STATIC ${SOURCES})
else()
	add_library(arch_sparc SHARED ${SOURCES})
endif()

option(CAPSTONE_BUILD_STATIC_RUNTIME "Embed static runtime" OFF)
option(CAPSTONE_BUILD_SHARED "Build shared library" OFF)
option(CAPSTONE_BUILD_TESTS "Build tests" OFF)
add_subdirectory(capstone)

target_link_libraries(arch_sparc binaryninjaapi capstone)

if(UNIX AND NOT APPLE)
	target_link_options(arch_sparc PRIVATE "LINKER:--exclude-libs,ALL")
endif()

set_target_properties(arch_sparc PROPERTIES
    CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

target_include_directories(arch_sparc PRIVATE ${PROJECT_SOURCE_DIR}/capstone/include)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_sparc)
	set_target_properties(arch_sparc PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()

if (DEFINED FORCE_TEST)
	set(TEST_LINK_LIBRARIES capstone)
	
	if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		add_executable(test_disasm test_disasm.cpp disassembler.cpp)

		target_compile_definitions(test_disasm PRIVATE FORCE_TEST=1)

		set_target_properties(test_disasm PROPERTIES
			CXX_STANDARD 17
			CXX_VISIBILITY_PRESET hidden
			CXX_STANDARD_REQUIRED ON
			VISIBILITY_INLINES_HIDDEN ON
			POSITION_INDEPENDENT_CODE ON)
		
		target_link_libraries(test_disasm PRIVATE ${TEST_LINK_LIBRARIES})

		endif()
endif()
