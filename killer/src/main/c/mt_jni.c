#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h> // Для mmap
#include <android/log.h>
#include "xhook.h"

#define LOG_TAG "KILLER"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

const char *apkPath__ = NULL;
const char *repPath__ = NULL;

// Хелпер: Получить путь к файлу по дескриптору (FD)
// Это позволяет нам понять, какой файл открыт, даже если мы проебали момент open
int get_path_from_fd(int fd, char *buf, size_t size) {
    if (fd < 0) return 0;
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link_path, buf, size - 1);
    if (len != -1) {
        buf[len] = '\0';
        return 1;
    }
    return 0;
}

int is_target_path(const char *path) {
    if (!path || !apkPath__) return 0;
    return strstr(path, "base.apk") != NULL;
}

// --- OPEN / OPENAT (КЛАССИКА) ---

int (*old_open)(const char *, int, mode_t) = NULL;
int openImpl(const char *pathname, int flags, mode_t mode) {
    if (is_target_path(pathname) && old_open) return old_open(repPath__, flags, mode);
    return old_open ? old_open(pathname, flags, mode) : -1;
}

int (*old_open64)(const char *, int, mode_t) = NULL;
int open64Impl(const char *pathname, int flags, mode_t mode) {
    if (is_target_path(pathname) && old_open64) return old_open64(repPath__, flags, mode);
    return old_open64 ? old_open64(pathname, flags, mode) : -1;
}

int (*old___open_2)(const char *, int) = NULL;
int __open_2Impl(const char *pathname, int flags) {
    if (is_target_path(pathname) && old___open_2) return old_open(repPath__, flags, 0); // Redirect to open
    return old___open_2 ? old___open_2(pathname, flags) : -1;
}

int (*old_openat)(int, const char*, int, mode_t) = NULL;
int openatImpl(int fd, const char *pathname, int flags, mode_t mode) {
    if (is_target_path(pathname) && old_openat) return old_openat(fd, repPath__, flags, mode);
    return old_openat ? old_openat(fd, pathname, flags, mode) : -1;
}

// --- FSTAT (ПРОВЕРКА РАЗМЕРА ПО ДЕСКРИПТОРУ) ---
// Если дескриптор указывает на грязный файл, fstat вернет грязный размер.
// Мы должны это исправить.

int (*old_fstat)(int, struct stat *) = NULL;
int fstatImpl(int fd, struct stat *buf) {
    char path[512];
    if (get_path_from_fd(fd, path, sizeof(path))) {
        if (is_target_path(path)) {
            // Подменяем на стат чистого файла!
            return stat(repPath__, buf); 
        }
    }
    return old_fstat ? old_fstat(fd, buf) : -1;
}

// --- MMAP (САМОЕ ВАЖНОЕ ДЛЯ ХЭШИРОВАНИЯ) ---
// Если игра открыла файл (даже через Java) и делает mmap -> мы подменяем маппинг.

void* (*old_mmap)(void *, size_t, int, int, int, off_t) = NULL;
void* mmapImpl(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    char path[512];
    // Проверяем, какой файл маппят
    if (fd >= 0 && get_path_from_fd(fd, path, sizeof(path))) {
        if (is_target_path(path)) {
            LOGD("Caught MMAP on base.apk! Redirecting to clean file.");
            
            // 1. Открываем чистый файл
            int clean_fd = old_open(repPath__, O_RDONLY, 0);
            if (clean_fd >= 0) {
                // 2. Маппим чистый файл вместо грязного
                void* res = old_mmap(addr, length, prot, flags, clean_fd, offset);
                close(clean_fd); // fd больше не нужен после mmap
                return res;
            }
        }
    }
    return old_mmap ? old_mmap(addr, length, prot, flags, fd, offset) : MAP_FAILED;
}

void* (*old_mmap64)(void *, size_t, int, int, int, off_t) = NULL;
void* mmap64Impl(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    char path[512];
    if (fd >= 0 && get_path_from_fd(fd, path, sizeof(path))) {
        if (is_target_path(path)) {
            LOGD("Caught MMAP64 on base.apk! Redirecting.");
            int clean_fd = old_open(repPath__, O_RDONLY, 0);
            if (clean_fd >= 0) {
                void* res = old_mmap64(addr, length, prot, flags, clean_fd, offset);
                close(clean_fd);
                return res;
            }
        }
    }
    return old_mmap64 ? old_mmap64(addr, length, prot, flags, fd, offset) : MAP_FAILED;
}


JNIEXPORT void JNICALL
Java_bin_mt_signature_KillerApplication_hookApkPath(JNIEnv *env, __attribute__((unused)) jclass clazz, jstring apkPath, jstring repPath) {
    apkPath__ = (*env)->GetStringUTFChars(env, apkPath, 0);
    repPath__ = (*env)->GetStringUTFChars(env, repPath, 0);

    LOGD("Installing Hooks...");
    const char* target_libs = "^/data/.*\\.so$";

    // OPEN
    xhook_register(target_libs, "open", openImpl, (void **) &old_open);
    xhook_register(target_libs, "open64", open64Impl, (void **) &old_open64);
    xhook_register(target_libs, "__open_2", __open_2Impl, (void **) &old___open_2);
    xhook_register(target_libs, "openat", openatImpl, (void **) &old_openat);

    // FSTAT (Размер файла)
    xhook_register(target_libs, "fstat", fstatImpl, (void **) &old_fstat);
    
    // MMAP (Чтение контента)
    xhook_register(target_libs, "mmap", mmapImpl, (void **) &old_mmap);
    xhook_register(target_libs, "mmap64", mmap64Impl, (void **) &old_mmap64);

    xhook_ignore(".*libkiller\\.so$", NULL);
    xhook_refresh(0);
}
