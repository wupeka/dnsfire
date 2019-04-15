cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG -ggdb -O2")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall -O3")
add_executable(dnsfire-ipsetd ipsetd.c siphash24.c lookup3.c dnsfire.c tht.c)
add_executable(dnsfire-cmdd cmdd.c siphash24.c lookup3.c dnsfire.c tht.c)
 