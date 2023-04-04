# CMake版本
cmake_minimum_required(VERSION 3.18.0)

# `std::make_unique`要求最低C++14
set(CMAKE_CXX_STANDARD 14)

# 加载自定义模块
include(cmake/tools.cmake)

# 工程名
project(suricata)


####################################### 添加pcap库 #######################################
if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
    find_library(PCAP_LIBRARIES NAMES wpcap HINTS ${PCAP_INCLUDE_DIR}/../Lib/x64) # 如果工程要生成32位的, 则不需要加x64
else ()
    if ("$ENV{PCAP_ROOT}" STREQUAL "") # 自动查找
        find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
    else () # 如果有手动配置PCAP环境变量PCAP_ROOT, 则从环境变量中获取
        set(PCAP_INCLUDE_DIR $ENV{PCAP_ROOT}/include)
    endif ()
    find_library(PCAP_LIBRARIES NAMES pcap HINTS ${PCAP_INCLUDE_DIR}/../lib)
endif ()
set(PCAP_ROOT_DIR ${PCAP_INCLUDE_DIR}/../)
message(STATUS "Pcap root dir: ${PCAP_ROOT_DIR}")
message(STATUS "Pcap include path: ${PCAP_INCLUDE_DIR}")
message(STATUS "Pcap libraries: ${PCAP_LIBRARIES}")
if ("${PCAP_ROOT_DIR}" STREQUAL "PCAP_ROOT_DIR-NOTFOUND" OR
        "${PCAP_INCLUDE_DIR}" STREQUAL "PCAP_INCLUDE_DIR-NOTFOUND" OR
        "${PCAP_LIBRARIES}" STREQUAL "PCAP_LIBRARIES-NOTFOUND")
    message(WARNING "Pcap not found")
    return()
else ()
    include_directories(${PCAP_INCLUDE_DIR})
endif ()


####################################### 添加线程库 #######################################
find_package(Threads REQUIRED)

####################################### 添加libhtp库 #######################################
if ("$ENV{LIBHTP_ROOT}" STREQUAL "") # 自动查找
    find_path(LIBHTP_INCLUDE_DIR NAMES htp.h)
else () # 如果有手动配置LIBHTP环境变量LIBHTP_ROOT, 则从环境变量中获取
    set(LIBHTP_INCLUDE_DIR $ENV{LIBHTP_ROOT}/include/htp)
endif ()
find_library(LIBHTP_LIBRARIES NAMES htp HINTS ${LIBHTP_INCLUDE_DIR}/../../lib)
set(LIBHTP_ROOT_DIR ${LIBHTP_INCLUDE_DIR}/../../)
message(STATUS "libhtp root dir: ${LIBHTP_ROOT_DIR}")
message(STATUS "libhtp include path: ${LIBHTP_INCLUDE_DIR}")
message(STATUS "libhtp libraries: ${LIBHTP_LIBRARIES}")
if ("${LIBHTP_ROOT_DIR}" STREQUAL "LIBHTP_ROOT_DIR-NOTFOUND" OR
    "${LIBHTP_INCLUDE_DIR}" STREQUAL "LIBHTP_INCLUDE_DIR-NOTFOUND" OR
    "${LIBHTP_LIBRARIES}" STREQUAL "LIBHTP_LIBRARIES-NOTFOUND")
    message(WARNING "libhtp not found")
    return()
else ()
    include_directories(${LIBHTP_INCLUDE_DIR})
endif ()
##########################################################################################
find_library (LIB_SURICATA_RUST libsuricata.a  "/opt/suricata-rust/" NO_DEFAULT_PATH)

message(STATUS "libsuricata rust root dir: ${LIB_SURICATA_RUST}")
message(STATUS "libsuricata rust libraries: ${LIB_SURICATA_RUST}")
if ("${LIB_SURICATA_RUST}" STREQUAL "LIB_SURICATA_RUST-NOTFOUND" )
    message(WARNING "libsuricata rust not found")
    return()
endif ()

add_definitions(-DHAVE_CONFIG_H=1)
add_definitions(-DLOCAL_STATE_DIR="/tmp")

include_directories(/usr/include/nss)
include_directories(/usr/include/nspr)
include_directories(src)
include_directories(rust/dist)
include_directories(rust/gen)




# 添加工程文件
set(proc_intrusion_files)
get_cxx_files(src src_list)
list(APPEND proc_intrusion_files ${src_list})

if (ENABLE_FILES_INFO) 
    print_info(BODY "proc_intrusion_files:")
    foreach(filename ${proc_intrusion_files})
        message("    " ${filename})
    endforeach()
endif()


# 构建可执行文件
add_executable(suricata ${proc_intrusion_files})


# 链接依赖库文件
target_link_libraries(suricata Threads::Threads
        ${LIB_SURICATA_RUST}
                                     ${PCAP_LIBRARIES}
                                     ${LIBHTP_LIBRARIES}
                                     dl
                                     rt
                                     m
                                     lz4
                                     magic
                                     cap-ng
                                     jansson
                                     yaml
                                     z
                                     pcre
                                     ssl3
                                     smime3
                                     nss3
                                     nssutil3
                                     plds4
                                     plc4
                                     nspr4
        )
