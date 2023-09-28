cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(sessionmgr-bin
    VERSION ${SESSIONMGR_VERSION}
    DESCRIPTION "Session Manager"
)

#SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

set(CMAKE_BUILD_TYPE Debug)

add_executable( ${PROJECT_NAME}
    src/sessionmgr.c
)

target_include_directories( ${PROJECT_NAME}
    PRIVATE ../client/inc
    PRIVATE inc
    PRIVATE .
)

target_link_libraries( ${PROJECT_NAME}
    rt
    sessionmgr
    varserver
    crypt
)

set_target_properties( ${PROJECT_NAME}
    PROPERTIES
    OUTPUT_NAME sessionmgr
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_compile_options( ${PROJECT_NAME}
	PRIVATE
	-Wall
	-Wextra
	-Wpedantic
	-Werror
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)