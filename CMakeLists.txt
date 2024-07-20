cmake_minimum_required(VERSION 3.28)
project(Protect)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(vendor/glm)
add_subdirectory(vendor/spdlog)

# Add include directories
include_directories(/usr/include/libnet)
include_directories(/usr/include/hiredis)
include_directories(./src)

# Enable it and fix all warnings
add_definitions ("-Wall")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions("-DGD_ENABLE_ASSERTS")
    add_definitions("-DGD_PROFILE=1")
endif()

# It can be disabled this way: cmake .. -DENABLE_NFQ_SUPPORT=OFF
option(ENABLE_NFQ_SUPPORT "Enable NFQ support" ON)

# Get last commit hash
# execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)

# Short 8 symbol commit
execute_process(
    COMMAND git rev-list HEAD -n 1
    COMMAND cut -c1-8
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH_SHORT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
        COMMAND git rev-list --count HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_COUNT
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Commit hash: ${GIT_LAST_COMMIT_HASH_SHORT}")

set (GD_VERSION_MAJOR 0)
set (GD_APPLICATION_VERSION "${GD_VERSION_MAJOR}.${GIT_COMMIT_COUNT} ${GIT_LAST_COMMIT_HASH_SHORT}")
add_definitions("-DGD_APPLICATION_VERSION=\"${GD_APPLICATION_VERSION}\"")
add_definitions("-DGD_APPLICATION=\"${PROJECT_NAME}\"")

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
        src/Guardian/Network/TcpConnection.cpp
        src/Guardian/Network/TcpConnection.h
        src/Guardian/Core/Log.cpp
        src/Guardian/Core/Log.h
        src/Guardian/Core/Assert.h
        src/Guardian/Guardian.h
        src/Guardian/Debug/Instrumentor.h
        src/Guardian/Core/Buffer.h
        src/Guardian/Network/Packet/Packet.cpp
        src/Guardian/Network/Packet/Packet.h
        src/Network/Detection/Mitigation.h
        src/Network/Detection/ICMP/IcmpFlood.h
        src/Guardian/Network/Protocol.h
        src/Guardian/Network/Packet/PacketAction.h
        src/Network/Detection/ICMP/IcmpFlood.cpp
        src/Network/Detection/TCP/SynFlood.h
        src/Network/Detection/TCP/SynFlood.cpp
        src/Network/Detection/UDP/DnsBlock.cpp
        src/Network/Detection/UDP/DnsBlock.h
        src/Guardian/Network/Http.cpp
        src/Guardian/Network/Http.h
)

# Link the required libraries
# target_link_libraries(${PROJECT_NAME} hiredis)
# target_link_libraries(${PROJECT_NAME} pthread)
target_link_libraries(${PROJECT_NAME} curl)
target_link_libraries(${PROJECT_NAME} netfilter_queue)
target_link_libraries(${PROJECT_NAME} spdlog)
target_link_libraries(${PROJECT_NAME} glm)
target_link_libraries(${PROJECT_NAME} ldns)
target_link_libraries(${PROJECT_NAME} /usr/lib/x86_64-linux-gnu/libnet.so)