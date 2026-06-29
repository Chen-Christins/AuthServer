cmake_minimum_required(VERSION 3.22)
project(LarkBot)

set(ROOT_DIR ${PROJECT_SOURCE_DIR})

include(cmake/utils.cmake)
include(cmake/common.cmake)
include(cmake/dependencies.cmake)

include_directories(.)
include_directories(${PROJECT_SOURCE_DIR}/protocol/include)

# 创建博客服务器模块
create_server_module(bot
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/bin/module
    ${PROJECT_SOURCE_DIR}/bin
    ""
)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin/module)
