
#include "Helper.h"

ScopeUtfString::ScopeUtfString(JNIEnv *jniEnv,jstring j_str) {
    _j_str = j_str;
    _c_str = jniEnv->GetStringUTFChars(j_str, nullptr);
}

ScopeUtfString::~ScopeUtfString() {
    getEnv()->ReleaseStringUTFChars(_j_str, _c_str);
}

ScopeUtfString::ScopeUtfString(jstring j_str) {
    _j_str = j_str;
    _c_str = getEnv()->GetStringUTFChars(j_str, nullptr);

}
