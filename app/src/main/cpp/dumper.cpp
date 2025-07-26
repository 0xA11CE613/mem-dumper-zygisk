#include <jni.h>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <dirent.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <thread>
#include <android/log.h>

#include "zygisk/zygisk.hpp"
#include "zygisk/logger.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define CHUNK_SIZE 65536

#define targetPackageName "com.example.package"
#define targetPackageLibrary "libexample.so"

#ifndef process_vm_readv
#include <sys/syscall.h>
#include <asm/unistd.h>
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
    return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

ssize_t read_process_memory(pid_t pid, uintptr_t address, void *value, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = (void*)address;
    remote[0].iov_len = size;
    return process_vm_readv(pid, local, 1, remote, 1, 0);
}

pid_t find_pid(const char *process_name) {
    DIR *dir = opendir("/proc");
    struct dirent *entry = nullptr;
    char cmdline_path[256];
    char cmdline[256];
    int fd;

    if (dir == nullptr) {
        return -1;
    }

    while ((entry = readdir(dir)) != nullptr) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0) || (entry->d_type != DT_DIR) || (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))) {
            continue;
        }

        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        fd = open(cmdline_path, O_RDONLY);

        read(fd, cmdline, 256);
        close(fd);
        if (strncmp(cmdline, process_name, strlen(process_name)) == 0) {
            closedir(dir);
            return atoi(entry->d_name);
        }
    }
    closedir(dir);
    return -1;
}

uint8_t get_module_address(pid_t process_id, const char *module_name, unsigned long long *start_addr, unsigned long long *end_addr) {
    char filename[256];
    char line[1024];
    FILE *fp = nullptr;
    uint8_t address_found = 0;
    unsigned long long start, end;

    snprintf(filename, sizeof(filename), "/proc/%d/maps", process_id);

    if (!(fp = fopen(filename, "r"))) {
        return 0;
    }
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
                address_found = 1;
                *start_addr = start;
                *end_addr = end;
                break;
            }
        }
    }
    fclose(fp);
    return address_found;
}

void convertBytes(long long bytes, char result[50]) {
    if (bytes < 0) {
        sprintf(result, "Invalid input: Negative bytes");
        return;
    }

    if (bytes < 1024) {
        sprintf(result, "%lld bytes", bytes);
    } else if (bytes < 1024 * 1024) {
        sprintf(result, "%.2f KB", (double)bytes / 1024);
    } else if (bytes < 1024 * 1024 * 1024) {
        sprintf(result, "%.2f MB", (double)bytes / (1024 * 1024));
    } else {
        sprintf(result, "%.2f GB", (double)bytes / (1024 * 1024 * 1024));
    }
}

void *main_thread(void *arg) {
    try {
        const char* package = targetPackageName;
        const char* module = targetPackageLibrary;
        unsigned long long start = 0, end = 0;
        char result[256];

        pid_t pid = find_pid(package);

        if (pid == -1) {
            LOGERRNO("Failed to open %s process", package);
            return reinterpret_cast<void *>(1);
        }

        if (!get_module_address(pid, module, &start, &end)) {
            LOGERRNO("Failed to get %s base module address from %s package", module, package);
            return reinterpret_cast<void *>(1);
        }

        convertBytes(end - start, result);
        LOGI("%s Module Size: %s", module, result);

        uint8_t chunk[CHUNK_SIZE];
        unsigned long long remaining_size = end - start;
        unsigned long long address = start;

        snprintf(result, sizeof(result), "/storage/emulated/0/%s_dump_%d.bin", module, pid);
        int fout = open(result, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (fout == -1) {
            LOGERRNO("Failed to create %s file", result);
            return reinterpret_cast<void *>(1);
        }

        while (remaining_size > 0) {
            size_t bytesToRead = remaining_size < CHUNK_SIZE ? remaining_size : CHUNK_SIZE;

            if (read_process_memory(pid, address, chunk, bytesToRead) != (ssize_t)bytesToRead) {
                LOGW("Unable to read memory at %p", (void*)address);
                break;
            }

            if (write(fout, chunk, bytesToRead) != (ssize_t)bytesToRead) {
                LOGERRNO("Failed to write to %s", result);
                close(fout);
                return reinterpret_cast<void *>(1);
            }

            remaining_size -= bytesToRead;
            address += bytesToRead;
        }

        close(fout);
        LOGI("Memory dump finished: %s", result);

    } catch (const std::exception &e) {
        LOGI("main_thread: Exception caught: %s", e.what());
    } catch (...) {
        LOGI("main_thread: Unknown exception caught!");
    }

    return nullptr;
}

static bool package_found = false;
char *package_data_dir = nullptr;

class memory_dumper : public zygisk::ModuleBase {
private:
    Api *api{};
    JNIEnv *env{};

    static int checkPackage(const char *package_name) {
        if (strcmp(package_name, targetPackageName) == 0) {
            LOGI("Package found as process: %s", package_name);
            return 1;
        }
        LOGERRNO("No match for: %s", package_name);
        return -1;
    }

public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (checkPackage(package_name) > 0) {
            package_found = true;
            package_data_dir = strdup(app_data_dir);
        } else {
            package_found = false;
        }
        env->ReleaseStringUTFChars(args->nice_name, package_name);
        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (package_found) {
            // Main
            std::thread(main_thread, package_data_dir).detach();
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *) override {}

    void postServerSpecialize(const ServerSpecializeArgs *) override {}
};

REGISTER_ZYGISK_MODULE(memory_dumper)