cmake_minimum_required(VERSION 3.10)

set(SESSIONMGR_VERSION 0.1)

# set the project name
project(sessionmgr
    VERSION ${SESSIONMGR_VERSION}
    DESCRIPTION "Session Manager"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(test)
