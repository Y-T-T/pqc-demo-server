add_subdirectory(fips202)

file(GLOB MLKEM_SOURCES "*.c")
add_library(mlkem ${MLKEM_SOURCES})

target_link_libraries(mlkem PUBLIC fips202)