cmake_minimum_required(VERSION 3.12)

project(PQC_SERVER)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(crypto)
add_subdirectory(kyber)
add_subdirectory(server)
add_subdirectory(tls)


set(SOURCE_FILES proxy_server.c)

add_executable(
    test_server
    
    ${SOURCE_FILES}
    ${SUBDIR_SOURCES}
    )

target_link_libraries(test_server PUBLIC crypto kyber server tls ${OPENSSL_LIBRARIES})