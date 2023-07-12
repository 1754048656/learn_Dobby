//
// VirtualApp Native Project
//
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
//#include <CydiaSubstrate.h>
//#include <Jni/VAJni.h>
#include <sys/stat.h>
#include <syscall.h>
#include <BinarySyscallFinder.h>
#include <climits>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <pthread.h>
#include <vector>
#include <HookUtils.h>
#include <BinarySyscallFinder.h>

#include "IORelocator.h"
#include "SandboxFs.h"
#include "canonicalize_md.h"
#include "Symbol.h"
#include "Log.h"
#include "VMHook.h"
#include "main.h"

void startIOHook(JNIEnv *env, int api_level, bool hook_dlopen);

bool need_load_env = true;
bool skip_kill = false;
bool debug_kill = false;
bool execve_process = false;

int g_preview_api_level = 0;
int g_api_level = 0;

int inline getArrayItemCount(char *const array[]) {
    int i;
    for (i = 0; array[i]; ++i);
    return i;
}

std::vector<std::string> Split(const std::string& s,
                               const std::string& delimiters) {
    CHECK_NE(delimiters.size(), 0U);

    std::vector<std::string> result;

    size_t base = 0;
    size_t found;
    while (true) {
        found = s.find_first_of(delimiters, base);
        result.push_back(s.substr(base, found - base));
        if (found == s.npos) break;
        base = found + 1;
    }

    return std::move(result);
}




void IOUniformer::init_env_before_all() {
    if (!need_load_env) {
        return;
    }
    //LOG(ERROR) << "init_env_before_all 开始执行 ";
    need_load_env = false;

    char *ld_preload = getenv("LD_PRELOAD");

    //LOG(ERROR) << "LD_PRELOAD 打印" << ld_preload ;
    if (!ld_preload || !strstr(ld_preload, "libIOHook.so")) {
        return;
    }
    execve_process = true;
    char *process_name = parse::get_process_name();
    LOG(ERROR) << "Start init env : %s" << process_name;
    free(process_name);
    char src_key[KEY_MAX];
    char dst_key[KEY_MAX];
    int i = 0;
    while (true) {
        memset(src_key, 0, sizeof(src_key));
        memset(dst_key, 0, sizeof(dst_key));
        sprintf(src_key, "V_REPLACE_ITEM_SRC_%d", i);
        sprintf(dst_key, "V_REPLACE_ITEM_DST_%d", i);
        char *src_value = getenv(src_key);
        if (!src_value) {
            break;
        }
        char *dst_value = getenv(dst_key);
        add_replace_item(src_value, dst_value);
        i++;
    }
    i = 0;
    while (true) {
        memset(src_key, 0, sizeof(src_key));
        sprintf(src_key, "V_KEEP_ITEM_%d", i);
        char *keep_value = getenv(src_key);
        if (!keep_value) {
            break;
        }
        add_keep_item(keep_value);
        i++;
    }
    i = 0;
    while (true) {
        memset(src_key, 0, sizeof(src_key));
        sprintf(src_key, "V_FORBID_ITEM_%d", i);
        char *forbid_value = getenv(src_key);
        if (!forbid_value) {
            break;
        }
        add_forbidden_item(forbid_value);
        i++;
    }
    char *api_level_char = getenv("V_API_LEVEL");
    char *preview_api_level_chars = getenv("V_PREVIEW_API_LEVEL");
    if (api_level_char != nullptr) {
        int api_level = atoi(api_level_char);
        g_api_level = api_level;
        int preview_api_level;
        preview_api_level = atoi(preview_api_level_chars);
        g_preview_api_level = preview_api_level;
        startIOHook(nullptr, api_level, true);
    }
}



void onSoLoaded(const char *name, void *handle);

void IOUniformer::relocate(const char *orig_path, const char *new_path) {
    add_replace_item(orig_path, new_path);
}

const char *IOUniformer::query(const char *orig_path, char *const buffer, const size_t size) {
    return relocate_path(orig_path, buffer, size);
}

void IOUniformer::whitelist(const char *_path) {
    add_keep_item(_path);
}

void IOUniformer::forbid(const char *_path) {
    add_forbidden_item(_path);
}

void IOUniformer::readOnly(const char *_path) {
    add_readonly_item(_path);
}

const char *IOUniformer::reverse(const char *_path, char *const buffer, const size_t size) {
    return reverse_relocate_path(_path, buffer, size);
}


__BEGIN_DECLS

// int faccessat(int dirfd, const char *pathname, int mode, int flags);
HOOK_DEF(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {
    ALOGE("faccessat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (relocated_path && !(mode & W_OK && isReadOnly(relocated_path))) {
        return syscall(__NR_faccessat, dirfd, relocated_path, mode, flags);
    }
    errno = EACCES;
    return -1;
}

// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
HOOK_DEF(int, fchmodat, int dirfd, const char *pathname, mode_t mode, int flags) {
    ALOGE("fchmodat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_fchmodat, dirfd, relocated_path, mode, flags);
    }
    errno = EACCES;
    return -1;
}

// int fstatat64(int dirfd, const char *pathname, struct stat *buf, int flags);
HOOK_DEF(int, fstatat64, int dirfd, const char *pathname, struct stat *buf, int flags) {
    ALOGE("fstatat64 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        long ret;
#if defined(__arm__) || defined(__i386__)
        ret = syscall(__NR_fstatat64, dirfd, relocated_path, buf, flags);
#else
        ret = syscall(__NR_newfstatat, dirfd, relocated_path, buf, flags);
#endif
        return ret;
    }
    errno = EACCES;
    return -1;
}

// int kill(pid_t pid, int sig);
HOOK_DEF(int, kill, pid_t pid, int sig) {
    ALOGE("kill >>> pid : %d, sig : %d", pid, sig);
    if (debug_kill && sig == 9) {
        abort();
    }
    if (skip_kill)
        return 1;
    return syscall(__NR_kill, pid, sig);
}

#ifndef __LP64__

// int __statfs64(const char *path, size_t size, struct statfs *stat);
HOOK_DEF(int, __statfs64, const char *pathname, size_t size, struct statfs *stat) {
    ALOGE("__statfs64 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_statfs64, relocated_path, size, stat);
    }
    errno = EACCES;
    return -1;
}

// int __open(const char *pathname, int flags, int mode);
HOOK_DEF(int, __open, const char *pathname, int flags, int mode) {
    ALOGE("__open 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (relocated_path && !((flags & O_WRONLY || flags & O_RDWR) && isReadOnly(relocated_path))) {
//        int fake_fd = redirect_proc_maps(relocated_path, flags, mode);
//        if (fake_fd != 0) {
//            return fake_fd;
//        }
        return syscall(__NR_open, relocated_path, flags, mode);
    }
    errno = EACCES;
    return -1;
}

// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
HOOK_DEF(ssize_t, readlink, const char *pathname, char *buf, size_t bufsiz) {
    ALOGE("readlink 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        long ret = syscall(__NR_readlink, relocated_path, buf, bufsiz);
        if (ret < 0) {
            return ret;
        } else {
            // relocate link content
            if (reverse_relocate_path_inplace(buf, bufsiz) != -1) {
                return ret;
            }
        }
    }
    errno = EACCES;
    return -1;
}

// int mkdir(const char *pathname, mode_t mode);
HOOK_DEF(int, mkdir, const char *pathname, mode_t mode) {
    ALOGE("mkdir 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_mkdir, relocated_path, mode);
    }
    errno = EACCES;
    return -1;
}

// int rmdir(const char *pathname);
HOOK_DEF(int, rmdir, const char *pathname) {
    ALOGE("rmdir 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_rmdir, relocated_path);
    }
    errno = EACCES;
    return -1;
}

// int lchown(const char *pathname, uid_t owner, gid_t group);
HOOK_DEF(int, lchown, const char *pathname, uid_t owner, gid_t group) {
    ALOGE("lchown 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_lchown, relocated_path, owner, group);
    }
    errno = EACCES;
    return -1;
}

// int utimes(const char *filename, const struct timeval *tvp);
HOOK_DEF(int, utimes, const char *pathname, const struct timeval *tvp) {
    ALOGE("utimes 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_utimes, relocated_path, tvp);
    }
    errno = EACCES;
    return -1;
}

// int link(const char *oldpath, const char *newpath);
HOOK_DEF(int, link, const char *oldpath, const char *newpath) {
    ALOGE("link 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp, sizeof(temp));
    if (relocated_path_old) {
        return syscall(__NR_link, relocated_path_old, newpath);
    }
    errno = EACCES;
    return -1;
}

// int access(const char *pathname, int mode);
HOOK_DEF(int, access, const char *pathname, int mode) {
    ALOGE("access 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));

    if (relocated_path && !(mode & W_OK && isReadOnly(relocated_path))) {
        return syscall(__NR_access, relocated_path, mode);
    }
    errno = EACCES;
    return -1;
}

// int chmod(const char *path, mode_t mode);
HOOK_DEF(int, chmod, const char *pathname, mode_t mode) {
    ALOGE("chmod 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_chmod, relocated_path, mode);
    }
    errno = EACCES;
    return -1;
}

// int chown(const char *path, uid_t owner, gid_t group);
HOOK_DEF(int, chown, const char *pathname, uid_t owner, gid_t group) {
    ALOGE("chown 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_chown, relocated_path, owner, group);
    }
    errno = EACCES;
    return -1;
}

// int lstat(const char *path, struct stat *buf);
HOOK_DEF(int, lstat, const char *pathname, struct stat *buf) {
    ALOGE("lstat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_lstat64, relocated_path, buf);
    }
    errno = EACCES;
    return -1;
}

// int stat(const char *path, struct stat *buf);
HOOK_DEF(int, stat, const char *pathname, struct stat *buf) {
    ALOGE("stat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        long ret = syscall(__NR_stat64, relocated_path, buf);
        if (isReadOnly(relocated_path)) {
            buf->st_mode &= ~S_IWGRP;
        }
        return ret;
    }
    errno = EACCES;
    return -1;
}

// int symlink(const char *oldpath, const char *newpath);
HOOK_DEF(int, symlink, const char *oldpath, const char *newpath) {
    ALOGE("symlink 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp, sizeof(temp));
    if (relocated_path_old) {
        return syscall(__NR_symlink, relocated_path_old, newpath);
    }
    errno = EACCES;
    return -1;
}

// int unlink(const char *pathname);
HOOK_DEF(int, unlink, const char *pathname) {
    ALOGE("unlink 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (relocated_path && !isReadOnly(relocated_path)) {
        return syscall(__NR_unlink, relocated_path);
    }
    errno = EACCES;
    return -1;
}

// int fchmod(const char *pathname, mode_t mode);
HOOK_DEF(int, fchmod, const char *pathname, mode_t mode) {
    ALOGE("fchmod 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_fchmod, relocated_path, mode);
    }
    errno = EACCES;
    return -1;
}


// int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
HOOK_DEF(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    ALOGE("fstatat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_fstatat64, dirfd, relocated_path, buf, flags);
    }
    errno = EACCES;
    return -1;
}

// int fstat(const char *pathname, struct stat *buf, int flags);
HOOK_DEF(int, fstat, const char *pathname, struct stat *buf) {
    ALOGE("fstat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_fstat64, relocated_path, buf);
    }
    errno = EACCES;
    return -1;
}

// int mknod(const char *pathname, mode_t mode, dev_t dev);
HOOK_DEF(int, mknod, const char *pathname, mode_t mode, dev_t dev) {
    ALOGE("mknod 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_mknod, relocated_path, mode, dev);
    }
    errno = EACCES;
    return -1;
}

// int rename(const char *oldpath, const char *newpath);
HOOK_DEF(int, rename, const char *oldpath, const char *newpath) {
    ALOGE("rename 回调  ");

    char temp_old[PATH_MAX], temp_new[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp_old, sizeof(temp_old));
    const char *relocated_path_new = relocate_path(newpath, temp_new, sizeof(temp_new));
    if (relocated_path_old && relocated_path_new) {
        return syscall(__NR_rename, relocated_path_old, relocated_path_new);
    }
    errno = EACCES;
    return -1;
}

#endif


// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
HOOK_DEF(int, mknodat, int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    ALOGE("mknodat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_mknodat, dirfd, relocated_path, mode, dev);
    }
    errno = EACCES;
    return -1;
}

// int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
HOOK_DEF(int, utimensat, int dirfd, const char *pathname, const struct timespec times[2],
         int flags) {
    ALOGE("utimensat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_utimensat, dirfd, relocated_path, times, flags);
    }
    errno = EACCES;
    return -1;
}

// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
HOOK_DEF(int, fchownat, int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
    ALOGE("fchownat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_fchownat, dirfd, relocated_path, owner, group, flags);
    }
    errno = EACCES;
    return -1;
}

// int chroot(const char *pathname);
HOOK_DEF(int, chroot, const char *pathname) {
    ALOGE("chroot 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_chroot, relocated_path);
    }
    errno = EACCES;
    return -1;
}

// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
HOOK_DEF(int, renameat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    ALOGE("renameat 回调  ");

    char temp_old[PATH_MAX], temp_new[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp_old, sizeof(temp_old));
    const char *relocated_path_new = relocate_path(newpath, temp_new, sizeof(temp_new));
    if (relocated_path_old && relocated_path_new) {
        return syscall(__NR_renameat, olddirfd, relocated_path_old, newdirfd,
                       relocated_path_new);
    }
    errno = EACCES;
    return -1;
}

// int statfs64(const char *__path, struct statfs64 *__buf) __INTRODUCED_IN(21);
HOOK_DEF(int, statfs64, const char *filename, struct statfs64 *buf) {
    ALOGE("statfs64 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(filename, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_statfs, relocated_path, buf);
    }
    errno = EACCES;
    return -1;
}

// int unlinkat(int dirfd, const char *pathname, int flags);
HOOK_DEF(int, unlinkat, int dirfd, const char *pathname, int flags) {
    ALOGE("unlinkat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (relocated_path && !isReadOnly(relocated_path)) {
        return syscall(__NR_unlinkat, dirfd, relocated_path, flags);
    }
    errno = EACCES;
    return -1;
}

// int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
HOOK_DEF(int, symlinkat, const char *oldpath, int newdirfd, const char *newpath) {
    ALOGE("symlinkat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp, sizeof(temp));
    if (relocated_path_old) {
        return syscall(__NR_symlinkat, relocated_path_old, newdirfd, newpath);
    }
    errno = EACCES;
    return -1;
}

// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
HOOK_DEF(int, linkat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
         int flags) {
    ALOGE("linkat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp, sizeof(temp));
    if (relocated_path_old) {
        return syscall(__NR_linkat, olddirfd, relocated_path_old, newdirfd, newpath,
                       flags);
    }
    errno = EACCES;
    return -1;
}

// int mkdirat(int dirfd, const char *pathname, mode_t mode);
HOOK_DEF(int, mkdirat, int dirfd, const char *pathname, mode_t mode) {
    ALOGE("mkdirat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_mkdirat, dirfd, relocated_path, mode);
    }
    errno = EACCES;
    return -1;
}

// int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
HOOK_DEF(int, readlinkat, int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    ALOGE("readlinkat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        long ret = syscall(__NR_readlinkat, dirfd, relocated_path, buf, bufsiz);
        if (ret < 0) {
            return ret;
        } else {
            // relocate link content
            if (reverse_relocate_path_inplace(buf, bufsiz) != -1) {
                return ret;
            }
        }
    }
    errno = EACCES;
    return -1;
}


// int truncate(const char *path, off_t length);
HOOK_DEF(int, truncate, const char *pathname, off_t length) {
    ALOGE("truncate 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_truncate, relocated_path, length);
    }
    errno = EACCES;
    return -1;
}

// int chdir(const char *path);
HOOK_DEF(int, chdir, const char *pathname) {
    ALOGE("chdir 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_chdir, relocated_path);
    }
    errno = EACCES;
    return -1;
}

// int __getcwd(char *buf, size_t size);
HOOK_DEF(int, __getcwd, char *buf, size_t size) {
    ALOGE("__getcwd 回调  ");

    long ret = syscall(__NR_getcwd, buf, size);
    if (!ret) {
        if (reverse_relocate_path_inplace(buf, size) < 0) {
            errno = EACCES;
            return -1;
        }
    }
    return ret;
}


// int __openat(int fd, const char *pathname, int flags, int mode);
HOOK_DEF(int, __openat, int fd, const char *pathname, int flags, int mode) {
    ALOGE("__openat 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));

    if (__predict_true(relocated_path)) {
//        int fake_fd = redirect_proc_maps(relocated_path, flags, mode);
//        if (fake_fd != 0) {
//            return fake_fd;
//        }
        return syscall(__NR_openat, fd, relocated_path, flags, mode);
    }
    errno = EACCES;
    return -1;
}

// int __statfs (__const char *__file, struct statfs *__buf);
HOOK_DEF(int, __statfs, __const char *__file, struct statfs *__buf) {
    ALOGE("__statfs 回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(__file, temp, sizeof(temp));
    if (__predict_true(relocated_path)) {
        return syscall(__NR_statfs, relocated_path, __buf);
    }
    errno = EACCES;
    return -1;
}

static struct sigaction old_sig_act{};
HOOK_DEF(int, sigaction, int sig, struct sigaction *new_act, struct sigaction *old_act) {
    ALOGE("sigaction 回调  ");

    if (sig != SIGABRT) {
        return orig_sigaction(sig, new_act, old_act);
    } else {
        if (old_act) {
            *old_act = old_sig_act;
        }
//        if (new_act) {
//            old_sig_act = *new_act;
//        }
        return 0;
    }
}

static char **relocate_envp(const char *pathname, char *const envp[]) {
    if (strstr(pathname, "libweexjsb.so")) {
        return const_cast<char **>(envp);
    }
    char *soPath = getenv("V_SO_PATH");
    char *soPath64 = getenv("V_SO_PATH_64");

    char *env_so_path = nullptr;
    FILE *fd = fopen(pathname, "r");
    if (!fd) {
        return const_cast<char **>(envp);
    }
    for (int i = 0; i < 4; ++i) {
        fgetc(fd);
    }
    int type = fgetc(fd);
    if (type == ELFCLASS32) {
        env_so_path = soPath;
    } else if (type == ELFCLASS64) {
        env_so_path = soPath64;
    }
    fclose(fd);
    if (env_so_path == NULL) {
        return const_cast<char **>(envp);
    }
    int len = 0;
    int ld_preload_index = -1;
    int self_so_index = -1;
    while (envp[len]) {
        /* find LD_PRELOAD element */
        if (ld_preload_index == -1 && !strncmp(envp[len], "LD_PRELOAD=", 11)) {
            ld_preload_index = len;
        }
        if (self_so_index == -1 && !strncmp(envp[len], "V_SO_PATH=", 10)) {
            self_so_index = len;
        }
        ++len;
    }
    /* append LD_PRELOAD element */
    if (ld_preload_index == -1) {
        ++len;
    }
    /* append V_env element */
    if (self_so_index == -1) {
        // V_SO_PATH
        // V_API_LEVEL
        // V_PREVIEW_API_LEVEL
        // V_NATIVE_PATH
        len += 4;
        if (soPath64) {
            // V_SO_PATH_64
            len++;
        }
        len += get_keep_item_count();
        len += get_forbidden_item_count();
        len += get_replace_item_count() * 2;
    }

    /* append NULL element */
    ++len;

    char **relocated_envp = (char **) malloc(len * sizeof(char *));
    memset(relocated_envp, 0, len * sizeof(char *));
    for (int i = 0; envp[i]; ++i) {
        if (i != ld_preload_index) {
            relocated_envp[i] = strdup(envp[i]);
        }
    }
    char LD_PRELOAD_VARIABLE[PATH_MAX];
    if (ld_preload_index == -1) {
        ld_preload_index = len - 2;
        sprintf(LD_PRELOAD_VARIABLE, "LD_PRELOAD=%s", env_so_path);
    } else {
        const char *orig_ld_preload = envp[ld_preload_index] + 11;
        // remove old preload va
        std::vector<std::string> paths;
        paths = Split(std::string(orig_ld_preload), ":");
        orig_ld_preload = nullptr;
        if (paths.size() > 0) {
            std::string new_ld_path_str;
            for (auto path : paths) {
                if (path.compare(soPath) != 0 && path.compare(soPath64) != 0) {
                    new_ld_path_str += path;
                    new_ld_path_str += ":";
                }
            }
            if (!new_ld_path_str.empty()) {
                orig_ld_preload = strdup(new_ld_path_str.c_str());
            }
        }
        if (orig_ld_preload) {
            sprintf(LD_PRELOAD_VARIABLE, "LD_PRELOAD=%s:%s", env_so_path, orig_ld_preload);
        } else {
            sprintf(LD_PRELOAD_VARIABLE, "LD_PRELOAD=%s", env_so_path);
        }
    }
    relocated_envp[ld_preload_index] = strdup(LD_PRELOAD_VARIABLE);
    int index = 0;
    while (relocated_envp[index]) index++;
    if (self_so_index == -1) {
        char element[PATH_MAX] = {0};
        sprintf(element, "V_SO_PATH=%s", soPath);
        relocated_envp[index++] = strdup(element);
        if (soPath64) {
            sprintf(element, "V_SO_PATH_64=%s", soPath64);
            relocated_envp[index++] = strdup(element);
        }
        sprintf(element, "V_API_LEVEL=%s", getenv("V_API_LEVEL"));
        relocated_envp[index++] = strdup(element);
        sprintf(element, "V_PREVIEW_API_LEVEL=%s", getenv("V_PREVIEW_API_LEVEL"));
        relocated_envp[index++] = strdup(element);
        sprintf(element, "V_NATIVE_PATH=%s", getenv("V_NATIVE_PATH"));
        relocated_envp[index++] = strdup(element);

        for (int i = 0; i < get_keep_item_count(); ++i) {
            PathItem &item = get_keep_items()[i];
            char env[PATH_MAX] = {0};
            sprintf(env, "V_KEEP_ITEM_%d=%s", i, item.path);
            relocated_envp[index++] = strdup(env);
        }

        for (int i = 0; i < get_forbidden_item_count(); ++i) {
            PathItem &item = get_forbidden_items()[i];
            char env[PATH_MAX] = {0};
            sprintf(env, "V_FORBID_ITEM_%d=%s", i, item.path);
            relocated_envp[index++] = strdup(env);
        }

        for (int i = 0; i < get_replace_item_count(); ++i) {
            ReplaceItem &item = get_replace_items()[i];
            char src[PATH_MAX] = {0};
            char dst[PATH_MAX] = {0};
            sprintf(src, "V_REPLACE_ITEM_SRC_%d=%s", i, item.orig_path);
            sprintf(dst, "V_REPLACE_ITEM_DST_%d=%s", i, item.new_path);
            relocated_envp[index++] = strdup(src);
            relocated_envp[index++] = strdup(dst);
        }
    }
    return relocated_envp;
}

//skip dex2oat hooker
bool isSandHooker(char *const args[]) {
    int orig_arg_count = getArrayItemCount(args);

    for (int i = 0; i < orig_arg_count; i++) {
        if (strstr(args[i], "SandHooker")) {
            if (g_api_level >= ANDROID_N) {
                ALOGE("skip dex2oat hooker!");
                return true;
            } else {
                return false;
            }
        }
    }
    return false;
}

//disable inline
char **build_new_argv(char *const argv[]) {

    int orig_argv_count = getArrayItemCount(argv);

    int new_argv_count = orig_argv_count + 2;
    char **new_argv = (char **) malloc(new_argv_count * sizeof(char *));
    int cur = 0;
    for (int i = 0; i < orig_argv_count; ++i) {
        new_argv[cur++] = argv[i];
    }

    //(api_level == 28 && g_preview_api_level > 0) = Android Q Preview
    if (g_api_level >= ANDROID_L2 && g_api_level < ANDROID_Q) {
        new_argv[cur++] = (char *) "--compile-pic";
    }
    if (g_api_level >= ANDROID_M) {
        new_argv[cur++] = (char *) (g_api_level > ANDROID_N2 ? "--inline-max-code-units=0" : "--inline-depth-limit=0");
    }

    new_argv[cur] = nullptr;

    return new_argv;
}


// int (*origin_execve)(const char *pathname, char *const argv[], char *const envp[]);
HOOK_DEF(int, execve, const char *pathname, char *argv[], char *const envp[]) {
    ALOGE("execve  回调  ");

    char temp[PATH_MAX];
    const char *relocated_path = relocate_path(pathname, temp, sizeof(temp));
    if (!relocated_path) {
        errno = EACCES;
        return -1;
    }

    char **new_argv = nullptr;

    if (strstr(pathname, "dex2oat")) {
        if (isSandHooker(argv)) {
            return -1;
        }
        new_argv = build_new_argv(argv);
    }

    char **relocated_envp = relocate_envp(relocated_path, envp);

    long ret = syscall(__NR_execve, relocated_path, new_argv != nullptr ? new_argv : argv, relocated_envp);
    if (relocated_envp != envp) {
        int i = 0;
        while (relocated_envp[i] != NULL) {
            free(relocated_envp[i]);
            ++i;
        }
        free(relocated_envp);
    }
    if (new_argv != nullptr) {
        free(new_argv);
    }
    return ret;
}

HOOK_DEF(void *, dlopen_CI, const char *filename, int flag) {
    ALOGE("dlopen_CI  回调  ");

    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(filename, temp, sizeof(temp));
    void *ret = orig_dlopen_CI(redirect_path, flag);
    onSoLoaded(filename, ret);
    return ret;
}

HOOK_DEF(void*, do_dlopen_CIV, const char *filename, int flag, const void *extinfo) {
    ALOGE("do_dlopen_CIV  回调  ");

    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(filename, temp, sizeof(temp));
    void *ret = orig_do_dlopen_CIV(redirect_path, flag, extinfo);
    onSoLoaded(filename, ret);
    return ret;
}

HOOK_DEF(void*, do_dlopen_CIVV, const char *name, int flags, const void *extinfo,
         void *caller_addr) {
    ALOGE("do_dlopen_CIVV  回调  ");

    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(name, temp, sizeof(temp));
    void *ret = orig_do_dlopen_CIVV(redirect_path, flags, extinfo, caller_addr);
    onSoLoaded(name, ret);
    return ret;
}

//void *dlsym(void *handle, const char *symbol)
HOOK_DEF(void*, dlsym, void *handle, char *symbol) {
    return orig_dlsym(handle, symbol);
}

HOOK_DEF(pid_t, vfork) {
    return fork();
}

HOOK_DEF(bool, SetCheckJniEnabled, void* vm, bool enbaled) {
    return orig_SetCheckJniEnabled(vm, false);
}

HOOK_DEF(bool, is_accessible, void* thiz, const std::string& file) {
    return true;
}

__END_DECLS
// end IO DEF


void onSoLoaded(const char *name, void *handle) {
    if(name!= nullptr) {
        ALOGD("so loaded: %s", name);
    }
}

bool relocate_art(JNIEnv *env, const char *art_path) {
    intptr_t art_addr, art_off, symbol;
    if ((art_addr = get_addr(art_path)) == 0) {
        ALOGE("Cannot found art addr.");
        return false;
    }

    //disable jni check
    if (g_api_level >= ANDROID_L && env && resolve_symbol(art_path, "_ZN3art9JavaVMExt18SetCheckJniEnabledEb",
                       &art_off) == 0) {
        symbol = art_addr + art_off;
        orig_SetCheckJniEnabled = reinterpret_cast<bool (*)(void *, bool)>(symbol);
        JavaVM *vm;
        env->GetJavaVM(&vm);
        orig_SetCheckJniEnabled(vm, false);
    }
    return true;
}

bool fuck_linker(const char *linker_path) {
    void *handle = dlopen("libsandhook-native.so", RTLD_NOW);

    if (!handle) {
        return false;
    }

    auto getSym = reinterpret_cast<void *(*)(const char*, const char*)>(dlsym(handle,
                                                                              "SandGetSym"));

    if (!getSym) {
        return false;
    }
    auto is_accessible_str = "__dl__ZN19android_namespace_t13is_accessibleERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE";
    void *is_accessible_addr = getSym(linker_path, is_accessible_str);
    if (is_accessible_addr) {
        HookUtils::Hooker(is_accessible_addr, (void *) new_is_accessible,
                       (void **) &orig_is_accessible);
    }

    return true;
}

bool relocate_linker(const char *linker_path) {
    intptr_t linker_addr, dlopen_off, symbol;
    if ((linker_addr = get_addr(linker_path)) == 0) {
        ALOGE("Cannot found linker addr.");
        return false;
    }
    if (resolve_symbol(linker_path, "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv",
                       &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIVV,
                       (void **) &orig_do_dlopen_CIVV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIVV,
                       (void **) &orig_do_dlopen_CIVV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIVV,
                       (void **) &orig_do_dlopen_CIVV);
        return true;
    } else if (
            resolve_symbol(linker_path, "__dl__Z20__android_dlopen_extPKciPK17android_dlextinfoPKv",
                           &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIVV,
                       (void **) &orig_do_dlopen_CIVV);
        return true;
    } else if (
            resolve_symbol(linker_path, "__dl___loader_android_dlopen_ext",
                           &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIVV,
                       (void **) &orig_do_dlopen_CIVV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl__Z9do_dlopenPKciPK17android_dlextinfo",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIV,
                       (void **) &orig_do_dlopen_CIV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl__Z8__dlopenPKciPKv",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIV,
                       (void **) &orig_do_dlopen_CIV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl___loader_dlopen",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_do_dlopen_CIV,
                       (void **) &orig_do_dlopen_CIV);
        return true;
    } else if (resolve_symbol(linker_path, "__dl_dlopen",
                              &dlopen_off) == 0) {
        symbol = linker_addr + dlopen_off;
        HookUtils::Hooker((void *) symbol, (void *) new_dlopen_CI,
                       (void **) &orig_dlopen_CI);
        return true;
    }
    return false;
}

#if defined(__aarch64__)
bool on_found_syscall_aarch64(const char *path, int num, void *func) {
    static int pass = 0;
    switch (num) {
        HOOK_SYSCALL(fchmodat)
        HOOK_SYSCALL(fchownat)
        HOOK_SYSCALL(renameat)
        HOOK_SYSCALL(mkdirat)
        HOOK_SYSCALL(mknodat)
        HOOK_SYSCALL(truncate)
        HOOK_SYSCALL(linkat)
        HOOK_SYSCALL(faccessat)
        HOOK_SYSCALL_(statfs)
        HOOK_SYSCALL_(getcwd)
        HOOK_SYSCALL_(openat)
        HOOK_SYSCALL(readlinkat)
        HOOK_SYSCALL(unlinkat)
        HOOK_SYSCALL(symlinkat)
        HOOK_SYSCALL(utimensat)
        HOOK_SYSCALL(chdir)
        HOOK_SYSCALL(execve)
        HOOK_SYSCALL(kill)
    }
    if (pass == 18) {
        return BREAK_FIND_SYSCALL;
    }
    return CONTINUE_FIND_SYSCALL;
}

bool on_found_linker_syscall_arch64(const char *path, int num, void *func) {
    static int pass = 0;
    switch (num) {
        case __NR_openat:
            MSHookFunction(func, (void *) new___openat, (void **) &orig___openat);
            return BREAK_FIND_SYSCALL;
    }
    if (pass == 5) {
        return BREAK_FIND_SYSCALL;
    }
    return CONTINUE_FIND_SYSCALL;
}
#else

bool on_found_linker_syscall_arm(const char *path, int num, void *func) {
    switch (num) {
        case __NR_openat:
            HookUtils::Hooker(func, (void *) new___openat, (void **) &orig___openat);
            break;
        case __NR_open:
            HookUtils::Hooker(func, (void *) new___open, (void **) &orig___open);
            break;
    }
    return CONTINUE_FIND_SYSCALL;
}

#endif

void InterruptHandler(int signum, siginfo_t* siginfo, void* uc) {
    ALOGE("Begin of abort() ###################################");
    old_sig_act.sa_sigaction(signum, siginfo, uc);
}

void startIOHook(JNIEnv *env, int api_level, bool hook_dlopen) {
    ALOGE("Starting IO Hook...");

    const char *linker = nullptr;
    const char *libc = nullptr;
    const char *art = nullptr;


    ALOGE("api_level %d ",api_level);
    if (api_level >= ANDROID_Q) {
        if (sizeof(void*) == 8) {
            art = "/apex/com.android.runtime/lib64/libart.so";
            linker = "/apex/com.android.runtime/bin/linker64";
            libc = "/apex/com.android.runtime/lib64/bionic/libc.so";
        } else {
            art = "/apex/com.android.runtime/lib/libart.so";
            linker = "/apex/com.android.runtime/bin/linker";
            libc = "/apex/com.android.runtime/lib/bionic/libc.so";
        }
    } else {
        if (sizeof(void*) == 8) {
            art = "/system/lib64/libart.so";
            linker = "/system/bin/linker64";
            libc = "/system/lib64/libc.so";
        } else {
            art = "/system/lib/libart.so";
            linker = "/system/bin/linker";
            libc = "/system/lib/libc.so";
        }
    }

    //void *handle = dlopen("libc.so", RTLD_NOW);
    //bool relocate_libc = relocate_linker(libc);

    ALOGE("libc  %s ",libc);

    void *handle = dlopen_compat(libc, RTLD_NOW);



    if (debug_kill) {
        struct sigaction sig{};
        sigemptyset(&sig.sa_mask);
        sig.sa_flags = SA_SIGINFO;
        sig.sa_sigaction = InterruptHandler;
        if (sigaction(SIGABRT, &sig, &old_sig_act) != -1) {
        }
        HOOK_SYMBOL(handle, sigaction);
    }


    if (api_level >= ANDROID_Q) {
        fuck_linker(linker);
    }
    relocate_art(env, art);

    if (handle) {
#if defined(__aarch64__)
        if (!findSyscalls(libc, on_found_syscall_aarch64)) {
            HOOK_SYMBOL(handle, fchownat);
            HOOK_SYMBOL(handle, renameat);
            HOOK_SYMBOL(handle, mkdirat);
            HOOK_SYMBOL(handle, mknodat);
            HOOK_SYMBOL(handle, truncate);
            HOOK_SYMBOL(handle, linkat);
            if (!(patchEnv.host_packageName && strstr(patchEnv.app_packageName, "org.telegram.messenger"))) {
                ALOGE("hook readlinkat %s", patchEnv.app_packageName);
                HOOK_SYMBOL(handle, readlinkat);
            }
            HOOK_SYMBOL(handle, unlinkat);
            HOOK_SYMBOL(handle, symlinkat);
            HOOK_SYMBOL(handle, utimensat);
            HOOK_SYMBOL(handle, chdir);
            HOOK_SYMBOL(handle, execve);
            HOOK_SYMBOL(handle, statfs64);
            HOOK_SYMBOL(handle, kill);
            HOOK_SYMBOL(handle, vfork);
            HOOK_SYMBOL(handle, fstatat64);
        }
        if (hook_dlopen) {
            findSyscalls(linker, on_found_linker_syscall_arch64);
        }
#else
        HOOK_SYMBOL(handle, faccessat);

        HOOK_SYMBOL(handle, __openat);

        HOOK_SYMBOL(handle, fchmodat);
        HOOK_SYMBOL(handle, fchownat);
        HOOK_SYMBOL(handle, renameat);
        HOOK_SYMBOL(handle, fstatat64);
        HOOK_SYMBOL(handle, __statfs);
        HOOK_SYMBOL(handle, __statfs64);
        HOOK_SYMBOL(handle, mkdirat);
        HOOK_SYMBOL(handle, mknodat);
        HOOK_SYMBOL(handle, truncate);
        HOOK_SYMBOL(handle, linkat);
        HOOK_SYMBOL(handle, readlinkat);
        HOOK_SYMBOL(handle, unlinkat);
        HOOK_SYMBOL(handle, symlinkat);
        HOOK_SYMBOL(handle, utimensat);
        HOOK_SYMBOL(handle, __getcwd);
        HOOK_SYMBOL(handle, chdir);
        HOOK_SYMBOL(handle, execve);
        HOOK_SYMBOL(handle, kill);
        HOOK_SYMBOL(handle, vfork);
        HOOK_SYMBOL(handle, access);
        HOOK_SYMBOL(handle, stat);
        HOOK_SYMBOL(handle, lstat);
        HOOK_SYMBOL(handle, fstatat);
        if (api_level <= 20) {
            HOOK_SYMBOL(handle, access);
            HOOK_SYMBOL(handle, stat);
            HOOK_SYMBOL(handle, lstat);
            HOOK_SYMBOL(handle, fstatat);
            HOOK_SYMBOL(handle, __open);
            HOOK_SYMBOL(handle, chmod);
            HOOK_SYMBOL(handle, chown);
            HOOK_SYMBOL(handle, rename);
            HOOK_SYMBOL(handle, rmdir);
            HOOK_SYMBOL(handle, mkdir);
            HOOK_SYMBOL(handle, mknod);
            HOOK_SYMBOL(handle, link);
            HOOK_SYMBOL(handle, unlink);
            HOOK_SYMBOL(handle, readlink);
            HOOK_SYMBOL(handle, symlink);
        }

#ifdef __arm__
        //hook dlopen 通过Linker进行Hook
        if (hook_dlopen && ! relocate_linker(linker)) {
            ALOGE("findSyscalls 执行完毕 ");
            findSyscalls(linker, on_found_linker_syscall_arm);
        }

#endif

#endif
//        if(handle) {
//            dlclose_compat(handle);
//        }
    }
    ALOGE("IO Hook 结束  ");

}


void
IOUniformer::startUniformer(
                            JNIEnv *env,
                            const char *so_path,
                            const char *so_path_64,
                            const char *native_path,
                            int api_level,
                            int preview_api_level) {
    char api_level_chars[56];
    char pre_api_level_chars[56];
    setenv("V_SO_PATH", so_path, 1);
//    setenv("V_SO_PATH_64", so_path_64, 1);
    sprintf(api_level_chars, "%i", api_level);

    setenv("V_API_LEVEL", api_level_chars, 1);
    sprintf(pre_api_level_chars, "%i", preview_api_level);
    setenv("V_PREVIEW_API_LEVEL", pre_api_level_chars, 1);
    setenv("V_API_LEVEL", api_level_chars, 1);
    setenv("V_NATIVE_PATH", native_path, 1);

    startIOHook(env,api_level, false);
}
