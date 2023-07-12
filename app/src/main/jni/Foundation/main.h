//
// Created by Zhenxi on 2021/5/26.
//

#include "Helper.h"
#include "IORelocator.h"
#include "jni.h"
#include "logging.h"
#include <HookUtils.h>
#include <parse.h>
#include <dlfcn_compat.h>
#include <dlfcn_nougat.h>



#ifndef INC_01_MAIN_H
#define INC_01_MAIN_H

#endif //INC_01_MAIN_H


#if defined(__LP64__)
#define LIB_ART_PATH "/system/lib64/libart.so"
#define LIB_ART_PATH_Q "/apex/com.android.runtime/lib64/libart.so"
#else
#define LIB_ART_PATH "/system/lib/libart.so"
#define LIB_ART_PATH_Q "/apex/com.android.runtime/lib/libart.so"
#endif


#define JNINativeMethodSize   sizeof(JNINativeMethod)


enum Action {
    kAllow,
    kAllowButWarn,
    kAllowButWarnAndToast,
    kDeny
};



