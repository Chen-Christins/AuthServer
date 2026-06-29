cmake_minimum_required(VERSION 3.22)
project(dbproxy_data)

set(LIB_SRC
    auth/data/oauth_clients_info.cc
    auth/data/oauth_users_info.cc
)
add_library(dbproxy_data ${LIB_SRC})
force_redefine_file_macro_for_sources(dbproxy_data)
