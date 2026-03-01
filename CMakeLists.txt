cmake_minimum_required(VERSION 3.18)
project(ThirdPersonNametag LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ThirdPersonNametag SHARED src/main.cpp)

if(ANDROID)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -fvisibility=hidden -ffunction-sections -fdata-sections -w")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -O2 -fvisibility=hidden -ffunction-sections -fdata-sections -w")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections,--strip-all -s")

    include(FetchContent)

    if(ANDROID_ABI STREQUAL "arm64-v8a")
        message("Building for android arm64-v8a")

        FetchContent_Declare(fmt
            GIT_REPOSITORY https://github.com/fmtlib/fmt.git
            GIT_TAG 10.2.1
        )
        FetchContent_MakeAvailable(fmt)

        FetchContent_Declare(preloader_android
            GIT_REPOSITORY https://github.com/LiteLDev/preloader-android.git
            GIT_TAG main
        )
        FetchContent_GetProperties(preloader_android)
        if(NOT preloader_android_POPULATED)
            FetchContent_Populate(preloader_android)
            file(READ "${preloader_android_SOURCE_DIR}/src/pl/Logger.h" LOGGER_CONTENT)
            string(REPLACE "#include <format>"       "#include <fmt/format.h>"   LOGGER_CONTENT "${LOGGER_CONTENT}")
            string(REPLACE "std::vformat"            "fmt::vformat"              LOGGER_CONTENT "${LOGGER_CONTENT}")
            string(REPLACE "std::make_format_args"   "fmt::make_format_args"     LOGGER_CONTENT "${LOGGER_CONTENT}")
            file(WRITE "${preloader_android_SOURCE_DIR}/src/pl/Logger.h" "${LOGGER_CONTENT}")
            add_subdirectory(${preloader_android_SOURCE_DIR} ${preloader_android_BINARY_DIR})
        endif()

        target_link_libraries(preloader PUBLIC fmt::fmt)
        target_link_libraries(ThirdPersonNametag PRIVATE preloader log)

    elseif(ANDROID_ABI STREQUAL "x86_64")
        message("Building for mcpelauncher-manifest x86_64")

        set_target_properties(ThirdPersonNametag PROPERTIES CXX_STANDARD 23)

        FetchContent_Declare(libhat
            GIT_REPOSITORY https://github.com/BasedInc/libhat.git
            GIT_TAG 69149a1cee5a0228492826bd71af1a32d73ed87e
            EXCLUDE_FROM_ALL
        )
        FetchContent_MakeAvailable(libhat)
        target_link_libraries(ThirdPersonNametag PRIVATE libhat::libhat)

    endif()

else()
    target_compile_definitions(ThirdPersonNametag PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()