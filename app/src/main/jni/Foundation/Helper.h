//
// VirtualApp Native Project
//

#ifndef NDK_HELPER
#define NDK_HELPER
#include <jni.h>

extern jclass nativeEngineClass;

//全局唯一
extern JavaVM * vm;

class ScopeUtfString {


public:

    ScopeUtfString(JNIEnv *jniEnv,jstring j_str);
    ScopeUtfString(jstring j_str);
    const char *c_str() {
        return _c_str;
    }
    JNIEnv *getEnv() {
        JNIEnv *env;
        vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
        return env;
    }
//    static void initVm(JavaVM * __vm){
//        vm=__vm;
//    }
    ~ScopeUtfString();

private:
    jstring _j_str;
    const char *_c_str;
};

#endif //NDK_HELPER
