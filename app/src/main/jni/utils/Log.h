//
// Created by Administrator on 2019/10/15.
//

#ifndef VMP_LOG_H
#define VMP_LOG_H


//#include <linux/uio.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <errno.h>
//#include <pthread.h>
//#include <string>

#include <android/log.h>

#define TAG "mikDobby"


#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__);




//static int log_fd = -1;
//static pthread_mutex_t log_init_lock = PTHREAD_MUTEX_INITIALIZER;
//// WARING 这里log打的数据多了要溢出
//int writev(const struct iovec *vecs, int count) {
//    ssize_t total = 0;
//    char buffer[8192];
//    memset(buffer, 0, sizeof(buffer));
//    char *start = buffer;
//    for(;count > 0; count--, vecs++) {
//        memcpy(start, vecs->iov_base, vecs->iov_len);
//        start += vecs->iov_len;
//        total += vecs->iov_len;
//    }
//    total = write(log_fd, buffer, (size_t)total);
//    return (int)total;
//}
//
//int write_to_kernel(int priority, const char *tag, const char *msg) {
//    struct iovec vec[3];
//    vec[0].iov_base = (unsigned char *) &priority;
//    vec[0].iov_len = 1;
//    vec[1].iov_base = (void *) tag;
//    vec[1].iov_len = strlen(tag) + 1;
//    vec[2].iov_base = (void *) msg;
//    vec[2].iov_len = strlen(msg) + 1;
//    ssize_t ret;
//    do {
//        ret = writev(vec, 3);
//    } while (ret < 0 && errno == EINTR);
//    return (int)ret;
//}
//
//int print_log_native(int buffid, int priority, const char *tag, const char *msg) {
//    pthread_mutex_lock(&log_init_lock);
//    if (log_fd == -1) {
//        if (access("/dev/log/main", W_OK) == 0) {
//            if (buffid == 0) {
//                log_fd = open("/dev/log/main", O_WRONLY | O_CLOEXEC);
//            } else {
//                return -1;
//            }
//        } else {
//            return -1;
//        }
//    }
//    pthread_mutex_unlock(&log_init_lock);
//    return write_to_kernel(priority, tag, msg);
//}
//
//
//int print_log_native(int buffid, int priority, const char *tag, const std::string msg1) {
//    pthread_mutex_lock(&log_init_lock);
//    if (log_fd == -1) {
//        if (access("/dev/log/main", W_OK) == 0) {
//            if (buffid == 0) {
//                log_fd = open("/dev/log/main", O_WRONLY | O_CLOEXEC);
//            } else {
//                return -1;
//            }
//        } else {
//            return -1;
//        }
//    }
//    pthread_mutex_unlock(&log_init_lock);
//    return write_to_kernel(priority, tag, msg1.c_str());
//}


#endif //VMP_LOG_H
