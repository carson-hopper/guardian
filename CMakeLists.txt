cmake_minimum_required(VERSION 3.28)
project(Protect)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(vendor/glm)
add_subdirectory(vendor/spdlog)

# Add include directories
include_directories(/usr/include/hiredis)
include_directories(/usr/include/lua5.4)
include_directories(./src)

# Enable it and fix all warnings
# add_definitions ("-Wall")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions("-DGD_ENABLE_ASSERTS")
    add_definitions("-DGD_PROFILE=1")
endif()

# It can be disabled this way: cmake .. -DENABLE_NFQ_SUPPORT=OFF
option(ENABLE_NFQ_SUPPORT "Enable NFQ support" ON)

add_executable(${PROJECT_NAME} src/Protect.cpp
        src/gdpch.h
        src/gdpch.cpp
        src/Guardian/Core/PlatformDetection.h
        src/Guardian/Core/EntryPoint.h
        src/Guardian/Core/Application.h
        src/Guardian/Core/Application.cpp
        src/Guardian/Core/Base.h
        src/Guardian/Core/Timer.h
        src/Guardian/Core/Timestep.h
        src/Guardian/Core/Time.cpp
        src/Guardian/Core/Time.h
        src/Guardian/Core/Layer.cpp
        src/Guardian/Core/Layer.h
        src/Guardian/Network/Packet/IpPacket.h
        src/Layer/NfqLayer.h
        src/Layer/NfqLayer.cpp
        src/Guardian/Network/Packet/IpPacket.cpp
        src/Network/Detection/Detection.h
        src/Network/Detection/Detection.cpp
        src/Network/Detection/TCP/SynFlood.h
        src/Network/Detection/TCP/SynFlood.cpp
        src/Guardian/Network/Packet/TcpPacket.cpp
        src/Guardian/Network/Packet/TcpPacket.h
        src/Network/Detection/ICMP/IcmpScan.cpp
        src/Network/Detection/ICMP/IcmpScan.h
        src/Guardian/Network/Packet/IcmpPacket.h
        src/Guardian/Network/Packet/IcmpPacket.cpp
        src/Network/Detection/TCP/SynStealthScan.cpp
        src/Network/Detection/TCP/SynStealthScan.h
        src/Guardian/Network/TcpConnection.cpp
        src/Guardian/Network/TcpConnection.h
        src/Network/Detection/TCP/ConnectionTracking.cpp
        src/Network/Detection/TCP/ConnectionTracking.h
        src/Guardian/Core/Log.cpp
        src/Guardian/Core/Log.h
        src/Guardian/Core/Assert.h
        src/Guardian/Guardian.h
        src/Guardian/Debug/Instrumentor.h
)

# Get last commit hash
# execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)

# Short 8 symbol commit
# execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 COMMAND cut -c1-8 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH_SHORT OUTPUT_STRIP_TRAILING_WHITESPACE)
set (GIT_LAST_COMMIT_HASH_SHORT "")

# message(STATUS "Commit hash: ${GIT_LAST_COMMIT_HASH_SHORT}")

set (PLP_VERSION_MAJOR 1)
set (PLP_VERSION_MINOR 2)
set (PLP_VERSION_PATCH 8)
set (PLP_APPLICATION_VERSION "${PLP_VERSION_MAJOR}.${PLP_VERSION_MINOR}.${PLP_VERSION_PATCH} ${GIT_LAST_COMMIT_HASH_SHORT}")

# Link the required libraries
target_link_libraries(${PROJECT_NAME} lua5.4)
target_link_libraries(${PROJECT_NAME} hiredis)
target_link_libraries(${PROJECT_NAME} pthread)
target_link_libraries(${PROJECT_NAME} pcap)
target_link_libraries(${PROJECT_NAME} netfilter_queue)
target_link_libraries(${PROJECT_NAME} spdlog)
target_link_libraries(${PROJECT_NAME} glm)