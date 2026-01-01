#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>
#include "xhook.h"

#define LOG_TAG "KILLER"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

const char *apkPath__ = NULL;
const char *repPath__ = NULL;

int is_target(const char *path) {
    if (!path || !apkPath__) return 0;
    if (strstr(path, "base.apk")) return 1;
    return 0;
}

// --- OPEN FAMILY ---
int (*old_open)(const char *, int, mode_t) = NULL;
int openImpl(const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname) && old_open) return old_open(repPath__, flags, mode);
    return old_open ? old_open(pathname, flags, mode) : -1;
}

int (*old_open64)(const char *, int, mode_t) = NULL;
int open64Impl(const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname) && old_open64) return old_open64(repPath__, flags, mode);
    return old_open64 ? old_open64(pathname, flags, mode) : -1;
}

int (*old___open_2)(const char *, int) = NULL;
int __open_2Impl(const char *pathname, int flags) {
    if (is_target(pathname) && old___open_2) return old___open_2(repPath__, flags);
    return old___open_2 ? old___open_2(pathname, flags) : -1;
}

// --- OPENAT FAMILY ---
int (*old_openat)(int, const char*, int, mode_t) = NULL;
int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname) && old_openat) return old_openat(fd, repPath__, flags, mode);
    return old_openat ? old_openat(fd, pathname, flags, mode) : -1;
}

int (*old_openat64)(int, const char*, int, mode_t) = NULL;
int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname) && old_openat64) return old_openat64(fd, repPath__, flags, mode);
    return old_openat64 ? old_openat64(fd, pathname, flags, mode) : -1;
}

int (*old___openat_2)(int, const char *, int) = NULL;
int __openat_2Impl(int fd, const char *pathname, int flags) {
    if (is_target(pathname) && old___openat_2) return old___openat_2(fd, repPath__, flags);
    return old___openat_2 ? old___openat_2(fd, pathname, flags) : -1;
}

// --- STDIO FAMILY ---
FILE* (*old_fopen)(const char *, const char *) = NULL;
FILE* fopenImpl(const char *pathname, const char *mode) {
    if (is_target(pathname) && old_fopen) return old_fopen(repPath__, mode);
    return old_fopen ? old_fopen(pathname, mode) : NULL;
}

FILE* (*old_fopen64)(const char *, const char *) = NULL;
FILE* fopen64Impl(const char *pathname, const char *mode) {
    if (is_target(pathname) && old_fopen64) return old_fopen64(repPath__, mode);
    return old_fopen64 ? old_fopen64(pathname, mode) : NULL;
}

// --- INSPECTORS ---
int (*old_access)(const char *, int) = NULL;
int accessImpl(const char *pathname, int mode) {
    if (is_target(pathname) && old_access) return old_access(repPath__, mode);
    return old_access ? old_access(pathname, mode) : -1;
}

int (*old_stat)(const char *, struct stat *) = NULL;
int statImpl(const char *pathname, struct stat *buf) {
    if (is_target(pathname) && old_stat) return old_stat(repPath__, buf);
    return old_stat ? old_stat(pathname, buf) : -1;
}

int (*old_lstat)(const char *, struct stat *) = NULL;
int lstatImpl(const char *pathname, struct stat *buf) {
    if (is_target(pathname) && old_lstat) return old_lstat(repPath__, buf);
    return old_lstat ? old_lstat(pathname, buf) : -1;
}

int (*old_fstatat)(int, const char*, struct stat*, int) = NULL;
int fstatatImpl(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (is_target(pathname) && old_fstatat) return old_fstatat(dirfd, repPath__, buf, flags);
    return old_fstatat ? old_fstatat(dirfd, pathname, buf, flags) : -1;
}

int (*old_fstatat64)(int, const char*, struct stat*, int) = NULL;
int fstatat64Impl(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (is_target(pathname) && old_fstatat64) return old_fstatat64(dirfd, repPath__, buf, flags);
    return old_fstatat64 ? old_fstatat64(dirfd, pathname, buf, flags) : -1;
}

JNIEXPORT void JNICALL
Java_bin_mt_signature_KillerApplication_hookApkPath(JNIEnv *env, __attribute__((unused)) jclass clazz, jstring apkPath, jstring repPath) {
    apkPath__ = (*env)->GetStringUTFChars(env, apkPath, 0);
    repPath__ = (*env)->GetStringUTFChars(env, repPath, 0);

    LOGD("Hooking started...");

    // =================================================================
    // ВОТ ЗДЕСЬ БЫЛА ОШИБКА. 
    // МЫ ХУКАЕМ ТОЛЬКО ЛИБЫ, ЗАГРУЖЕННЫЕ ИЗ /data/ (ПРИЛОЖЕНИЕ)
    // ЭТО ИГНОРИРУЕТ /system/lib64/libc.so, libart.so и прочие
    // =================================================================
    const char* target_libs = "^/data/.*\\.so$";

    xhook_register(target_libs, "open", openImpl, (void **) &old_open);
    xhook_register(target_libs, "open64", open64Impl, (void **) &old_open64);
    xhook_register(target_libs, "__open_2", __open_2Impl, (void **) &old___open_2);

    xhook_register(target_libs, "openat", openatImpl, (void **) &old_openat);
    xhook_register(target_libs, "openat64", openat64Impl, (void **) &old_openat64);
    xhook_register(target_libs, "__openat_2", __openat_2Impl, (void **) &old___openat_2);

    xhook_register(target_libs, "fopen", fopenImpl, (void **) &old_fopen);
    xhook_register(target_libs, "fopen64", fopen64Impl, (void **) &old_fopen64);

    xhook_register(target_libs, "access", accessImpl, (void **) &old_access);
    xhook_register(target_libs, "stat", statImpl, (void **) &old_stat);
    xhook_register(target_libs, "lstat", lstatImpl, (void **) &old_lstat);
    xhook_register(target_libs, "fstatat", fstatatImpl, (void **) &old_fstatat);
    xhook_register(target_libs, "fstatat64", fstatat64Impl, (void **) &old_fstatat64);

    // Игнорируем свою собственную либу, чтобы не хукать свои же вызовы
    xhook_ignore(".*libkiller\\.so$", NULL); 

    xhook_refresh(0);
    LOGD("Hooks installed successfully.");
}
