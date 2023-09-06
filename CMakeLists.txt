cmake_minimum_required(VERSION 3.26)
project(AES C)

set(CMAKE_C_STANDARD 11)

set(MAIN_C ./testAES.c ./AES.c)

add_executable(AES ${MAIN_C})

add_definitions(-D _GEN_RAND_KEY)

target_link_libraries(AES "C:/Windows/System32/bcrypt.dll")

