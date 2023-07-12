//
// Created by Administrator on 2020-10-31.
//

#include <jni.h>
#include "test.h"
#include "hide.h"

extern "C"
void test::TestB(JNIEnv *env, jobject thiz_or_clazz) {
    LOG(ERROR) << "BBBBBBBBBBB";
}

static JNINativeMethod gMethods[] = {
        {"TestB", "()V",  (void *) test::TestB},
};


jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {

    LOG(ERROR) << "TestB  JNI_OnLoad 开始加载";
    //在 onload 改变 指定函数 函数地址 替换成自己的
    JNIEnv *env = nullptr;


    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_OK) {
        jclass MainClass = (jclass) env->NewGlobalRef(
                env->FindClass("com/mik/dobbydemo/MainActivity"));

        if (env->RegisterNatives(MainClass, gMethods, 1) < 0) {
            return JNI_ERR;
        }
        const  char* so_names[2];
        so_names[0] = "/system/lib/libriru_edxp.so";
        so_names[1] = "/system/lib/libdobby.so";
        riru_hide(so_names,2);

        return JNI_VERSION_1_6;
    }
    LOG(ERROR) << "TestB  JNI_OnLoad over";

    return 0;

}