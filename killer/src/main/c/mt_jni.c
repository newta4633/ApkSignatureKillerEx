#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "xhook.h"

const char *apkPath__ = NULL;
const char *repPath__ = NULL;

int is_target(const char *path) {
    if (!path || !apkPath__) return 0;
    if (strstr(path, "base.apk")) return 1;
    return 0;
}

// --- OPEN FAMILY ---

int (*old_open)(const char *, int, mode_t);
int openImpl(const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname)) return old_open(repPath__, flags, mode);
    return old_open(pathname, flags, mode);
}

int (*old_open64)(const char *, int, mode_t);
int open64Impl(const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname)) return old_open64(repPath__, flags, mode);
    return old_open64(pathname, flags, mode);
}

int (*old___open_2)(const char *, int);
int __open_2Impl(const char *pathname, int flags) {
    if (is_target(pathname)) return old_open(repPath__, flags, 0);
    return old___open_2(pathname, flags);
}

// --- OPENAT FAMILY ---

int (*old_openat)(int, const char*, int, mode_t);
int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname)) return old_openat(fd, repPath__, flags, mode);
    return old_openat(fd, pathname, flags, mode);
}

int (*old_openat64)(int, const char*, int, mode_t);
int openat64Impl(int fd, const char *pathname, int flags, mode_t mode) {
    if (is_target(pathname)) return old_openat64(fd, repPath__, flags, mode);
    return old_openat64(fd, pathname, flags, mode);
}

int (*old___openat_2)(int, const char *, int);
int __openat_2Impl(int fd, const char *pathname, int flags) {
    if (is_target(pathname)) return old_openat(fd, repPath__, flags, 0);
    return old___openat_2(fd, pathname, flags);
}

// --- STDIO FAMILY ---

FILE* (*old_fopen)(const char *, const char *);
FILE* fopenImpl(const char *pathname, const char *mode) {
    if (is_target(pathname)) return old_fopen(repPath__, mode);
    return old_fopen(pathname, mode);
}

FILE* (*old_fopen64)(const char *, const char *);
FILE* fopen64Impl(const char *pathname, const char *mode) {
    if (is_target(pathname)) return old_fopen64(repPath__, mode);
    return old_fopen64(pathname, mode);
}

// --- METADATA FAMILY ---

int (*old_access)(const char *, int);
int accessImpl(const char *pathname, int mode) {
    if (is_target(pathname)) return old_access(repPath__, mode);
    return old_access(pathname, mode);
}

int (*old_stat)(const char *, struct stat *);
int statImpl(const char *pathname, struct stat *buf) {
    if (is_target(pathname)) return old_stat(repPath__, buf);
    return old_stat(pathname, buf);
}

int (*old_lstat)(const char *, struct stat *);
int lstatImpl(const char *pathname, struct stat *buf) {
    if (is_target(pathname)) return old_lstat(repPath__, buf);
    return old_lstat(pathname, buf);
}

int (*old_fstatat)(int, const char*, struct stat*, int);
int fstatatImpl(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (is_target(pathname)) return old_fstatat(dirfd, repPath__, buf, flags);
    return old_fstatat(dirfd, pathname, buf, flags);
}

int (*old_fstatat64)(int, const char*, struct stat*, int);
int fstatat64Impl(int dirfd, const char *pathname, struct stat *buf, int flags) {
    if (is_target(pathname)) return old_fstatat64(dirfd, repPath__, buf, flags);
    return old_fstatat64(dirfd, pathname, buf, flags);
}

JNIEXPORT void JNICALL
Java_bin_mt_signature_KillerApplication_hookApkPath(JNIEnv *env, __attribute__((unused)) jclass clazz, jstring apkPath, jstring repPath) {
    apkPath__ = (*env)->GetStringUTFChars(env, apkPath, 0);
    repPath__ = (*env)->GetStringUTFChars(env, repPath, 0);

    xhook_register(".*\\.so$", "open", openImpl, (void **) &old_open);
    xhook_register(".*\\.so$", "open64", open64Impl, (void **) &old_open64);
    xhook_register(".*\\.so$", "__open_2", __open_2Impl, (void **) &old___open_2);

    xhook_register(".*\\.so$", "openat", openatImpl, (void **) &old_openat);
    xhook_register(".*\\.so$", "openat64", openat64Impl, (void **) &old_openat64);
    xhook_register(".*\\.so$", "__openat_2", __openat_2Impl, (void **) &old___openat_2);

    xhook_register(".*\\.so$", "fopen", fopenImpl, (void **) &old_fopen);
    xhook_register(".*\\.so$", "fopen64", fopen64Impl, (void **) &old_fopen64);

    xhook_register(".*\\.so$", "access", accessImpl, (void **) &old_access);
    xhook_register(".*\\.so$", "stat", statImpl, (void **) &old_stat);
    xhook_register(".*\\.so$", "lstat", lstatImpl, (void **) &old_lstat);
    xhook_register(".*\\.so$", "fstatat", fstatatImpl, (void **) &old_fstatat);
    xhook_register(".*\\.so$", "fstatat64", fstatat64Impl, (void **) &old_fstatat64);

    xhook_refresh(0);
}
