cmake_minimum_required(VERSION 2.8)

project(Crypto)

include_directories(include)
file(GLOB SOURCES "src/*.cpp")

add_executable(Crypto ${SOURCES})