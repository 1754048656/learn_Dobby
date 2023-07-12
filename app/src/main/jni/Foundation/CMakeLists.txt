cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

#添加内联支持
enable_language(C ASM)



include_directories(
        syscall/
        ../utils/
        ../inlineHook/
        ../dlfc/

)


add_library(
        IOHook

        SHARED

        main.cpp

        syscall/BinarySyscallFinder.cpp
        canonicalize_md.c
        IORelocator.cpp
        Helper.cpp
        #如果重定向Map相关可能会需要
        #src/main/jni/Foundation/syscall/MapsRedirector.cpp
        SandboxFs.cpp
        Symbol.cpp

        #src/main/jni/Foundation/syscall/VMHook.cpp
        ../utils/HookUtils.cpp
        ../utils/parse.cpp

        ../dlfc/dlfcn_compat.cpp
        ../dlfc/dlfcn_nougat.cpp

)

find_library(
        log-lib

        log
)

target_link_libraries(
        IOHook
        dobby
        ${log-lib}

)