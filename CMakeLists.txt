cmake_minimum_required(VERSION 3.26)
project(AES C)

set(CMAKE_C_STANDARD 11)

add_executable(AES main.c
        AES.c
        AES.h)

target_link_libraries(AES "C:/Windows/System32/bcrypt.dll")
