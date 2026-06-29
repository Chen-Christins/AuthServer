# dependencies.cmake

# Auto-detect chen-sdk directory by pattern "chen-sdk-*"
file(GLOB CHEN_SDK_DIRS "${PROJECT_SOURCE_DIR}/chen-sdk-*")
if (CHEN_SDK_DIRS)
    list(GET CHEN_SDK_DIRS 0 CHEN_SDK_DIR)
    message(STATUS "Using CHEN_SDK_DIR=${CHEN_SDK_DIR}")
else()
    message(FATAL_ERROR "chen-sdk-* not found under ${PROJECT_SOURCE_DIR}. Please fetch chen-sdk.")
endif()

include_directories(${CHEN_SDK_DIR}/include)

add_subdirectory(${CHEN_SDK_DIR})
