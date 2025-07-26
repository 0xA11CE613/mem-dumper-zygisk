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

ssize_t process_vm_readv(pid_t pid,
                         const struct iovec *local_iov,
                         unsigned long liovcnt,
                         const struct iovec *remote_iov,
                         unsigned long riovcnt,
                         unsigned long flags) {
    LOGI("process_vm_readv: pid = %d, liovcnt = %lu, riovcnt = %lu, flags = %lu", pid, liovcnt,
         riovcnt, flags);
    LOGI("Local iov base: %p, len: %lu", local_iov[0].iov_base, local_iov[0].iov_len);
    LOGI("Remote iov base: %p, len: %lu", remote_iov[0].iov_base, remote_iov[0].iov_len);

    ssize_t result = syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt,
                             flags);

    if (result == -1) {
        LOGE("process_vm_readv: syscall failed (errno = %d: %s)", errno, strerror(errno));
    } else {
        LOGI("process_vm_readv: successfully read %zd bytes", result);
    }

    return result;
}

#endif

ssize_t read_process_memory(pid_t pid, uintptr_t address, void *value, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = (void *) address;
    remote[0].iov_len = size;

    LOGI("read_process_memory: pid = %d, address = 0x%lx, size = %zu", pid, address, size);

    ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);

    if (nread == -1) {
        LOGE("read_process_memory: Failed to read memory from pid %d at 0x%lx (errno = %d: %s)",
             pid, address, errno, strerror(errno));
    } else {
        LOGI("read_process_memory: Successfully read %zd bytes from pid %d at 0x%lx", nread, pid,
             address);
    }

    return nread;
}

pid_t find_pid() {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *cmdline = fopen(cmdline_path, "r");
        if (!cmdline) continue;

        char raw[256] = {0};
        size_t len = fread(raw, 1, sizeof(raw) - 1, cmdline);
        fclose(cmdline);
        if (len == 0) continue;

        char actual_cmd[256] = {0};
        strncpy(actual_cmd, raw, sizeof(actual_cmd) - 1);

        if (strcmp(actual_cmd, "zygote64") == 0) {
            closedir(proc_dir);
            return pid;
        }
    }

    closedir(proc_dir);
    return -1;
}

uint8_t
get_module_address(pid_t process_id, const char *module_name, unsigned long long *start_addr,
                   unsigned long long *end_addr) {
    char filename[256];
    char line[1024];
    FILE *fp = nullptr;
    uint8_t address_found = 0;
    unsigned long long start, end;

    snprintf(filename, sizeof(filename), "/proc/%d/maps", process_id);
    LOGI("Opening maps file: %s", filename);

    if (!(fp = fopen(filename, "r"))) {
        LOGE("Failed to open %s", filename);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        // LOGI("maps line: %s", line);

        if (strstr(line, module_name)) {
            LOGI("Found module name match: %s", line);
            if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
                address_found = 1;
                *start_addr = start;
                *end_addr = end;
                LOGI("Parsed address range: 0x%llx - 0x%llx", start, end);
                break;
            } else {
                LOGE("Failed to parse address range from line: %s", line);
            }
        }
    }

    if (!address_found) {
        LOGE("Module '%s' not found in maps for PID %d", module_name, process_id);
    }

    fclose(fp);
    return address_found;
}

bool get_module_address_self(const char *libname, uint64_t *start, uint64_t *end) {
    LOGI("Searching for library: %s", libname);

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return false;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        //LOGI("maps line: %s", line);

        if (strstr(line, libname)) {
            if (sscanf(line, "%llx-%llx", start, end) == 2) {
                LOGI("Found %s: start = 0x%llx, end = 0x%llx", libname, *start, *end);
                fclose(fp);
                return true;
            } else {
                LOGE("Failed to parse line: %s", line);
            }
        }
    }

    fclose(fp);
    LOGE("Library %s not found in /proc/self/maps", libname);
    return false;
}

void convertBytes(long long bytes, char result[50]) {
    if (bytes < 0) {
        sprintf(result, "Invalid input: Negative bytes");
        LOGE("convertBytes: Invalid input, bytes = %lld", bytes);
        return;
    }

    if (bytes < 1024) {
        sprintf(result, "%lld bytes", bytes);
        LOGI("convertBytes: %lld bytes", bytes);
    } else if (bytes < 1024 * 1024) {
        double kb = (double) bytes / 1024;
        sprintf(result, "%.2f KB", kb);
        LOGI("convertBytes: %.2f KB", kb);
    } else if (bytes < 1024 * 1024 * 1024) {
        double mb = (double) bytes / (1024 * 1024);
        sprintf(result, "%.2f MB", mb);
        LOGI("convertBytes: %.2f MB", mb);
    } else {
        double gb = (double) bytes / (1024 * 1024 * 1024);
        sprintf(result, "%.2f GB", gb);
        LOGI("convertBytes: %.2f GB", gb);
    }
}

void *main_thread(void *arg) {
    try {
        LOGI("main_thread: Creation succeeded");

        const char *package = targetPackageName;
        const char *module = targetPackageLibrary;
        uint8_t library;
        unsigned long long start = 0, end = 0;
        char result[256];

        pid_t pid = find_pid();
        if (pid == -1) {
            LOGERRNO("Failed to find package: %s", package);
            return reinterpret_cast<void *>(1);
        }
        LOGI("Found PID: %d for package: %s", pid, package);

        do {
            library = get_module_address(pid, module, &start, &end);
            if (!library) sleep(1);
        } while (!library);
        /*while (!get_module_address_self(module, reinterpret_cast<uint64_t *>(&start),
                                        reinterpret_cast<uint64_t *>(&end))) {
            sleep(1);
        }*/

        LOGI("Found library at: %llx - %llx", start, end);

        LOGI("Found module address start: %llu, end: %llu", start, end);

        convertBytes(end - start, result);
        LOGI("%s Module Size: %s", module, result);

        uint8_t chunk[CHUNK_SIZE];
        unsigned long long remaining_size = end - start;
        unsigned long long address = start;

        LOGI("Dumping the library");
        snprintf(result, sizeof(result),
                 "/data/data/%s/files/%s_dump_%d.bin",
                 package, module, pid);
        int fout = open(result, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (fout == -1) {
            LOGERRNO("Failed to create %s file", result);
            return reinterpret_cast<void *>(1);
        }

        while (remaining_size > 0) {
            size_t bytesToRead = remaining_size < CHUNK_SIZE ? remaining_size : CHUNK_SIZE;

            if (read_process_memory(pid, address, chunk, bytesToRead) != (ssize_t) bytesToRead) {
                LOGW("Unable to read memory at %p", (void *) address);
                break;
            }

            if (write(fout, chunk, bytesToRead) != (ssize_t) bytesToRead) {
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