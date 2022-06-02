cmake_minimum_required(VERSION 2.8)

project(MemtesterSimple C)
add_executable(memtester-simple memtester-simple.c tests.c)
install(TARGETS memtester-simple DESTINATION bin)
