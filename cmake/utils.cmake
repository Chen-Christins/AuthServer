# 支持两种排除模式：
# 1. 相对路径模式：相对于 dir
# 2. 通配符模式：支持 ** 表示任意多级目录

# 使用示例：
# 1. 排除 src/gateway/grpc
# chen_set_sources(src SOURCES gateway/grpc)
#
# 2. 排除任何层级的 test 目录
# chen_set_sources(src SOURCES "**/test")
#
# 3. 排除任何以 mock 结尾的目录
# chen_set_sources(src SOURCES "**/mock")

function(chen_set_sources dir varname)
    set(exclude_patterns "")
    if(${ARGC} GREATER 2)
        foreach(i RANGE 2 ${ARGC}-1)
            list(APPEND exclude_patterns "${ARGV${i}}")
        endforeach()
    endif()

    chen_collect_sources(${dir} _tmp_sources "${exclude_patterns}")
    set(${varname} ${_tmp_sources} PARENT_SCOPE)
endfunction()

function(chen_collect_sources dir outputlist exclude_patterns)
    file(GLOB_RECURSE all_sources
        ${dir}/*.cc
        ${dir}/*.cpp
        ${dir}/*.c
    )

    if(exclude_patterns)
        foreach(pattern ${exclude_patterns})
            # 判断是否是通配符模式（包含 **）
            if(pattern MATCHES "\\*\\*")
                # 通配符模式：将 ** 替换为 .*
                string(REPLACE "**" ".*" regex_pattern "${pattern}")
            else()
                # 相对路径模式：转换为完整路径
                set(regex_pattern "${dir}/${pattern}")
            endif()

            # 转义路径分隔符
            string(REPLACE "/" "[/\\\\]" regex_pattern "${regex_pattern}")
            # 确保匹配完整路径
            set(regex_pattern ".*${regex_pattern}.*")

            # 排除匹配的文件
            list(FILTER all_sources EXCLUDE REGEX "${regex_pattern}")
        endforeach()
    endif()

    list(SORT all_sources)
    set(${outputlist} ${all_sources} PARENT_SCOPE)
endfunction()

# 修改__FILE__的宏
function(force_redefine_file_macro_for_sources targetname)
    get_target_property(source_files "${targetname}" SOURCES)
    foreach(sourcefile ${source_files})
        # Get source file's current list of compile definitions.
        get_property(defs SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS)
        # Get the relative path of the source file in project directory
        get_filename_component(filepath "${sourcefile}" ABSOLUTE)
        string(REPLACE ${PROJECT_SOURCE_DIR}/ "" relpath ${filepath})
        list(APPEND defs "__FILE__=\"${relpath}\"")
        # Set the updated compile definitions on the source file.
        set_property(
            SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS ${defs}
        )
    endforeach()
endfunction()

# ragel有限状态机
function(ragelmaker src_rl outputlist outputdir)
    #Create a custom build step that will call ragel on the provided src_rl file.
    #The output .cc file will be appended to the variable name passed in outputlist.

    get_filename_component(src_file ${src_rl} NAME_WE)

    set(rl_out ${outputdir}/${src_file}.cc)

    #adding to the list inside a function takes special care, we cannot use list(APPEND...)
    #because the results are local scope only
    set(${outputlist} ${${outputlist}} ${rl_out} PARENT_SCOPE)

    #Warning: The " -S -M -l -C -T0  --error-format=msvc" are added to match existing window invocation
    #we might want something different for mac and linux
    add_custom_command(
        OUTPUT ${rl_out}
        COMMAND cd ${outputdir}
        COMMAND ragel ${CMAKE_CURRENT_SOURCE_DIR}/${src_rl} -o ${rl_out} -l -C -G2 --error-format=msvc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${src_rl}
    )
    set_source_files_properties(${rl_out} PROPERTIES GENERATED TRUE)
endfunction(ragelmaker)

# 封装Protobuf文件生成逻辑（仿照ragelmaker风格）
# 功能：根据传入的.proto文件，生成对应的.cc/.h文件，并将.cc文件添加到指定的输出列表
# 参数说明：
#   src_proto - 输入的.proto文件路径（相对/绝对路径均可）
#   outputlist - 要追加生成文件的列表变量名（如LIB_SRC）
#   outputdir - 生成文件的输出目录（默认使用.proto文件所在目录）
function(protobuf_maker src_proto outputlist outputdir)
    # 获取绝对路径并检查是目录还是文件
    get_filename_component(abs_path ${src_proto} ABSOLUTE)
    
    # 初始化输出列表
    set(temp_list "")
    
    if(IS_DIRECTORY ${abs_path})
        # 如果是目录，遍历目录下所有.proto文件
        file(GLOB proto_files "${abs_path}/*.proto")
        foreach(proto_file ${proto_files})
            protobuf_maker_single(${proto_file} temp_list ${outputdir})
        endforeach()
    else()
        # 如果是单个文件，直接处理
        protobuf_maker_single(${src_proto} temp_list ${outputdir})
    endif()
    
    # 将结果返回给调用者
    set(${outputlist} ${temp_list} PARENT_SCOPE)
endfunction(protobuf_maker)

# 内部函数：处理单个proto文件
function(protobuf_maker_single src_proto outputlist outputdir)
    # 1. 路径处理（兼容相对/绝对路径，提取文件名）
    # 获取.proto文件的绝对路径（避免相对路径混乱）
    get_filename_component(proto_abs_path ${src_proto} ABSOLUTE)
    # 提取文件名（不含后缀），比如rpc.proto -> rpc
    get_filename_component(proto_file_we ${proto_abs_path} NAME_WE)
    # 提取.proto文件所在目录（用于protoc的-I参数）
    get_filename_component(proto_dir ${proto_abs_path} DIRECTORY)

    # 2. 确定输出目录（如果未指定，默认使用.proto文件所在目录）
    if(NOT outputdir)
        set(outputdir ${proto_dir})
    endif()
    # 确保输出目录存在
    file(MAKE_DIRECTORY ${outputdir})

    # 3. 定义生成的文件路径（.cc和.h）
    set(proto_cc ${outputdir}/${proto_file_we}.pb.cc)
    set(proto_h ${outputdir}/${proto_file_we}.pb.h)

    # 4. 将生成的.cc文件追加到列表
    list(APPEND ${outputlist} ${proto_cc})
    set(${outputlist} ${${outputlist}} PARENT_SCOPE)

    # 5. 生成protobuf文件的自定义命令（核心逻辑）
    add_custom_command(
        OUTPUT ${proto_cc} ${proto_h} # 输出的.cc/.h文件
        COMMAND protoc # protoc可执行程序
        # protoc参数：指定输出目录、导入目录、输入.proto文件
        ARGS --cpp_out=${outputdir} -I${proto_dir} ${proto_abs_path}
        DEPENDS ${proto_abs_path} # 依赖的.proto文件（文件变化时重新生成）
        COMMENT "Generating Protobuf file: ${proto_file_we}.pb.cc/h" # 友好的日志提示
    )

    # 6. 标记生成的文件为GENERATED（避免CMake误判文件不存在）
    set_source_files_properties(${proto_cc} ${proto_h} PROPERTIES GENERATED TRUE)

endfunction(protobuf_maker_single)

# 简化cmake文件
function(chen_add_executable targetname srcs depends libs)
    add_executable(${targetname} ${srcs})
    if(depends)
        add_dependencies(${targetname} ${depends})
    endif()
    force_redefine_file_macro_for_sources(${targetname})
    target_link_libraries(${targetname} ${libs})
endfunction()

# 设置目标的输出目录
# RUNTIME_OUTPUT_DIRECTORY：控制可执行文件（.exe）的输出目录
# LIBRARY_OUTPUT_DIRECTORY：控制库文件（.dll/.so）的输出目录
# ARCHIVE_OUTPUT_DIRECTORY：控制静态库（.lib/.a）的输出目录
function(chen_set_target_output_dir targetname outputdir)
    set_target_properties(${targetname} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${outputdir}"
        LIBRARY_OUTPUT_DIRECTORY "${outputdir}"
        ARCHIVE_OUTPUT_DIRECTORY "${outputdir}"
    )
endfunction()

# 封装创建服务器模块的函数
function(create_server_module module_name source_dir module_output_dir server_output_dir db_libs)
    chen_set_sources(${source_dir} MODULE_SOURCES)
    add_library(${module_name} SHARED ${MODULE_SOURCES})
    if(db_libs)
        target_link_libraries(${module_name} PRIVATE ${db_libs})
    endif()

    # 设置链接库变量
    string(TOUPPER ${module_name} MODULE_UPPER)
    set(libs
        ${CHEN_LIBRARY}
        ${CHEN_SDK_DEP_LIBS}
    )
    message(STATUS "[DEBUG] create_server_module libs=${libs}")
    set(${MODULE_UPPER}_LIBS ${libs} PARENT_SCOPE)
    
    force_redefine_file_macro_for_sources(${module_name})
    chen_set_target_output_dir(${module_name} "${module_output_dir}")

    # 服务器程序
    # chen_add_executable(${module_name}_server "src/${module_name}.cc" "" "${libs}")
    # chen_set_target_output_dir(${module_name}_server "${server_output_dir}")
endfunction()
