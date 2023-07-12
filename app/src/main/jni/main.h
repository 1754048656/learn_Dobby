//
// Created by Administrator on 2020-08-20.
//

#ifndef FENXIANG_MAIN_H
#define FENXIANG_MAIN_H


#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils/FileUtils.h"
#include "encrypt/Base64Utils.h"

#include "utils/Log.h"
#include "utils/logging.h"
#include "string"
#include <string>
#include <regex>
#include <bits/getopt.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <asm/fcntl.h>
#include "main.h"
#include "encrypt/Md5Utils.h"
#include "utils/parse.h"
#include "dobby.h"
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>


void RegisterNativeTest(JNIEnv *env, jobject jclazz, jstring str);

#endif //FENXIANG_MAIN_H
