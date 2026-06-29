# common.cmake - 编译配置和选项

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 设置C和C++标准
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置构建类型及编译选项
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    set(TEST ON)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# 全局编译选项 - 对所有目标生效
add_compile_options(
    -rdynamic
    -Wall
    -fPIC
    -Wno-deprecated
    # -Werror
    -Wno-unused-function
    -Wno-builtin-macro-redefined
    -Wno-deprecated-declarations
    -Wno-use-after-free
)