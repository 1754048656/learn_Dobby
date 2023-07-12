
#include "main.h"




JavaVM *vm;
jclass nativeEngineClass;

bool bypassGetFieldAction() {
    return kAllow;
}

bool bypassGetMethodAction() {
    return kAllow;
}

bool bypassShouldBlockAccessToField() {
    return false;
}

bool bypassShouldBlockAccessToMethod() {
    return false;
}

/**
 * 为了解决高版本反射限制的
 */
void bypassHiddenAPIEnforcementPolicy(int apiLevel, int previewApiLevel) {

    if (previewApiLevel > 0) {
        apiLevel++;
    }
    void *handle = fake_dlopen(apiLevel >= 29 ? LIB_ART_PATH_Q : LIB_ART_PATH, 0);


    void *symbol = fake_dlsym(handle,
                              "_ZN3art9hiddenapi25ShouldBlockAccessToMemberINS_8ArtFieldEEEbPT_PNS_6ThreadENSt3__18functionIFbS6_EEENS0_12AccessMethodE");
    if (symbol) {
        HookUtils::Hooker(symbol, (void *) &bypassShouldBlockAccessToField, (void **) nullptr);
    }
    symbol = fake_dlsym(handle,
                        "_ZN3art9hiddenapi25ShouldBlockAccessToMemberINS_9ArtMethodEEEbPT_PNS_6ThreadENSt3__18functionIFbS6_EEENS0_12AccessMethodE");
    if (symbol) {
        HookUtils::Hooker(symbol, (void *) &bypassShouldBlockAccessToMethod, (void **) nullptr);
    }

    symbol = fake_dlsym(handle,
                        "_ZN3art9hiddenapi6detail19GetMemberActionImplINS_8ArtFieldEEENS0_6ActionEPT_NS_20HiddenApiAccessFlags7ApiListES4_NS0_12AccessMethodE");
    if (symbol) {
        HookUtils::Hooker(symbol, (void *) &bypassGetFieldAction, (void **) nullptr);
    }
    symbol = fake_dlsym(handle,
                        "_ZN3art9hiddenapi6detail19GetMemberActionImplINS_9ArtMethodEEENS0_6ActionEPT_NS_20HiddenApiAccessFlags7ApiListES4_NS0_12AccessMethodE");
    if (symbol) {
        HookUtils::Hooker(symbol, (void *) &bypassGetMethodAction, (void **) nullptr);
    }
    fake_dlclose(handle);
}

static void
jni_nativeEnableIORedirect(JNIEnv *env, jclass, jstring soPath, jstring soPath64,
                           jstring nativePath, jint apiLevel,
                           jint preview_api_level) {

    ScopeUtfString so_path(soPath);
    ScopeUtfString so_path_64(soPath64);
    ScopeUtfString native_path(nativePath);

    //开启IO重定向
    IOUniformer::startUniformer(env, so_path.c_str(),
                                so_path_64.c_str(),
                                native_path.c_str(),
                                apiLevel,
                                preview_api_level);
}

static void jni_nativeIOWhitelist(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::whitelist(path.c_str());
}

static void jni_nativeIOForbid(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::forbid(path.c_str());
}

static void jni_nativeIOReadOnly(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::readOnly(path.c_str());
}


static void jni_nativeIORedirect(JNIEnv *env, jclass jclazz, jstring origPath, jstring newPath) {
    ScopeUtfString orig_path(origPath);
    ScopeUtfString new_path(newPath);
    IOUniformer::relocate(orig_path.c_str(), new_path.c_str());

}

static jstring jni_nativeGetRedirectedPath(JNIEnv *env, jclass jclazz, jstring origPath) {
    ScopeUtfString orig_path(origPath);
    char buffer[PATH_MAX];
    const char *redirected_path = IOUniformer::query(orig_path.c_str(), buffer, sizeof(buffer));
    if (redirected_path != nullptr) {
        return env->NewStringUTF(redirected_path);
    }
    return nullptr;
}

static void jni_bypassHiddenAPIEnforcementPolicy(JNIEnv *env, jclass jclazz, jint apiLevel,
                                                 jint previewApiLevel) {
    bypassHiddenAPIEnforcementPolicy(apiLevel, previewApiLevel);
}


static jstring jni_nativeReverseRedirectedPath(JNIEnv *env, jclass jclazz, jstring redirectedPath) {
    ScopeUtfString redirected_path(redirectedPath);
    char buffer[PATH_MAX];
    const char *orig_path = IOUniformer::reverse(redirected_path.c_str(), buffer, sizeof(buffer));
    return env->NewStringUTF(orig_path);
}


static JNINativeMethod methods[] = {
        {"nativeReverseRedirectedPath",            "(Ljava/lang/String;)Ljava/lang/String;",                      (void *) jni_nativeReverseRedirectedPath},
        {"nativeGetRedirectedPath",                "(Ljava/lang/String;)Ljava/lang/String;",                      (void *) jni_nativeGetRedirectedPath},
        {"nativeIORedirect",                       "(Ljava/lang/String;Ljava/lang/String;)V",                     (void *) jni_nativeIORedirect},
        {"nativeIOWhitelist",                      "(Ljava/lang/String;)V",                                       (void *) jni_nativeIOWhitelist},
        {"nativeIOForbid",                         "(Ljava/lang/String;)V",                                       (void *) jni_nativeIOForbid},
        {"nativeIOReadOnly",                       "(Ljava/lang/String;)V",                                       (void *) jni_nativeIOReadOnly},
        {"nativeEnableIORedirect",                 "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V", (void *) jni_nativeEnableIORedirect},
        {"nativeBypassHiddenAPIEnforcementPolicy", "(II)V",                                                       (void *) jni_bypassHiddenAPIEnforcementPolicy},
};


jint JNICALL JNI_OnLoad(JavaVM *_vm, void *reserved) {
    LOG(ERROR) << "IOHook  JNI_OnLoad 开始加载";
    //初始化Vmp方便字符串回收
    vm = _vm;

    JNIEnv *env = nullptr;

    if (_vm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_OK) {

        auto MainClass = (jclass) env->NewGlobalRef(
                env->FindClass("com/mik/dobbydemo/IO/NativeEngine"));


        if (env->RegisterNatives(MainClass, methods, sizeof(methods) / JNINativeMethodSize) < 0) {

            LOG(ERROR) << "IOHook JNI_ERR ";

            return JNI_ERR;
        }

        LOG(ERROR) << "IOHook JNI_OnLoad 注册成功";

        return JNI_VERSION_1_6;
    }

    LOG(ERROR) << "IOHook  JNI_OnLoad 加载失败";

    return 0;
}


/**
 * 主要为了兼容execve多进程问题
 * 比onload还在在initArray里面
 */
extern "C" __attribute__((constructor))
void _init(void) {

    LOG(ERROR) << "IO init_env_before_all 函数开始执行 " << parse::get_process_name();
    IOUniformer::init_env_before_all();
    LOG(ERROR) << "IO init_env_before_all 执行完毕";

}