cmake_minimum_required(VERSION 3.10)

# set the project name
project(sessionmgr
	VERSION ${SESSIONMGR_VERSION}
	DESCRIPTION "Session Manager Interface Functions"
)

include(GNUInstallDirs)

#add the library
add_library( ${PROJECT_NAME} SHARED
 	src/sessionmgr.c
)

set_target_properties( ${PROJECT_NAME} PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

target_link_libraries( ${PROJECT_NAME}
	rt
	varserver
)

set(SESSIONMGR_HEADERS
    inc/sessionmgr/sessionmgr.h
)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
    PUBLIC_HEADER "${SESSIONMGR_HEADERS}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_include_directories( ${PROJECT_NAME} PRIVATE . )

target_include_directories( ${PROJECT_NAME} PUBLIC inc )

target_compile_options( ${PROJECT_NAME}
	PRIVATE
	-Wall
	-Wextra
	-Wpedantic
	-Werror
)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sessionmgr)
