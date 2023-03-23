#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>

/////////////////////////////////////////////////////////////////////////
// RedCrow Lab - http://www.redcrowlab.com
// rcDetectVirtual - PoC Tool for determining if you are running in a VM.

/////////////////////////////////////////////////////////////////////////
// Check for virtualization using CPUID
bool check_cpuid() {
        unsigned int eax, ebx, ecx, edx;
        char hypervisor_name[13] = {0};

        // Inline assembly to acess registers
        eax = 0x1;
         __asm__ __volatile__("cpuid"
                                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                                : "a"(eax));

        if (ecx & (1 << 31)) {
                eax = 0x40000000;
                 __asm__ __volatile__("cpuid"
                                        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                                        : "a"(eax));
                memcpy(hypervisor_name, &ebx, 4);
                memcpy(hypervisor_name + 4, &ecx, 4);
                memcpy(hypervisor_name + 8, &edx, 4);

                printf("Hypervisor name: %s\n", hypervisor_name);
                return true;
        }

    return false;
}


////////////////////////////////////////////////////////////////////////////
// Check for virtualization using the Interrupt Descriptor Table
// IDT descriptor
typedef struct {
        uint16_t limit;
        uint32_t base;
} __attribute__((packed)) idt_descriptor_t;


bool check_idt() {
        idt_descriptor_t idt_desc;

        __asm__ __volatile__("sidt %0"
                                : "=m"(idt_desc)
                                :
                                : "memory");

        uintptr_t high_byte = (idt_desc.base >> 24) & 0xFF;

        if (high_byte == 0xFF || high_byte == 0x00) {
                return true;
        }

        return false;
}


/////////////////////////////////////////////////////////////////////////
// Check for virtualization using native C process table parsing
bool check_process_list() {
        DIR *proc_dir;
        struct dirent *entry;
        bool found = false;
        const char *search_terms[] = {
                "kvm", "qemu", "vbox", "vmware", NULL
        };

        if ((proc_dir = opendir("/proc")) == NULL) {
                perror("Error opening /proc");
                return false;
        }

        while ((entry = readdir(proc_dir)) != NULL) {
                // Check if the entry name is a number (indicating a process ID)
                if (isdigit(entry->d_name[0])) {
                        char exe_path[256];
                        char exe_target[256];
                        ssize_t len;

                        snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", entry->d_name);
                        len = readlink(exe_path, exe_target, sizeof(exe_target) - 1);

                        if (len != -1) {
                                exe_target[len] = '\0';
                                for (int i = 0; search_terms[i] != NULL; i++) {
                                        if (strcasestr(exe_target, search_terms[i]) != NULL) {
                                                printf("Detected process: %s\n", exe_target);
                                                found = true;
                                        }
                                }
                        }
                }
        }

        closedir(proc_dir);
        return found;
}


////////////////////////////////////////////////////////////////////
// Attempt to detect virtualization by reading the Machine Status Word
bool check_msw() {
        uint16_t msw;

        // Inline assembly to read register
         __asm__ __volatile__("smsw %0"
                                : "=rm"(msw)
                                :
                                : "memory");

        if ((msw & 0x100) == 0) {
                return true;
        }

        return false;
}


//////////////////////////////////////////////////////////////////
// Check using the timestamp counter values
bool check_tsc() {

    uint64_t tsc_before, tsc_after;
    uint32_t eax, ebx, ecx, edx;

        // Inline Assembly to read registers
         __asm__ __volatile__("rdtsc"
                                : "=a"(eax), "=d"(edx));

        tsc_before = ((uint64_t)edx << 32) | eax;

         __asm__ __volatile__("cpuid"
                                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                                : "a"(0x0));

         __asm__ __volatile__("rdtsc"
                                : "=a"(eax), "=d"(edx));

        tsc_after = ((uint64_t)edx << 32) | eax;

        uint64_t tsc_difference = tsc_after - tsc_before;

        // Adjust the threshold value according to your system
        const uint64_t threshold = 1000;

        if (tsc_difference > threshold) {
                return true;
        }

        return false;
}


//////////////////////////////////////////////////////////////////
// Check for virtualization using SMBIOS tables
bool check_smbios() {
        printf("Checking SMBIOS for potential Virtualization\n");
        const char *dmi_file = "/sys/firmware/dmi/tables/DMI";
        const char *virtualization_signatures[] = {
                "VMware", "VirtualBox", "QEMU", "KVM", "Xen", "Microsoft Virtual", NULL
        };

        FILE *file = fopen(dmi_file, "rb");

        if (!file) {
                perror("Unable to open DMI file");
                return false;
        }

        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        uint8_t *file_content = (uint8_t *)malloc(file_size);

        if (!file_content) {
                perror("Failed to allocate memory for DMI file content");
                fclose(file);
                return false;
        }

        size_t read_len = fread(file_content, 1, file_size, file);
        fclose(file);

        if (read_len != file_size) {
                perror("Unable to read DMI file");
                free(file_content);
                return false;
        }

        bool found = false;
        for (const char **sig = virtualization_signatures; *sig; ++sig) {
                const size_t sig_len = strlen(*sig);
                for (uint8_t *ptr = file_content; ptr < file_content + file_size - sig_len; ++ptr) {
                        if (memcmp(ptr, *sig, sig_len) == 0) {
                                found = true;
                                break;
                        }
                }

                if (found) {
                        break;
                }
        }

        free(file_content);
        return found;
}


//////////////////////////////////////////////////////////////////
// Detect virtualization by checking hardware under sys
bool check_hw_devices() {

        const char *hw_device_names[] = {
                "VirtualBox", "VMware", "QEMU", "KVM", "Xen", "Microsoft Corporation Hyper-V", NULL
        };

        DIR *dir = opendir("/sys/class");
        if (!dir) {
                perror("Failed to open /sys/class");
                return false;
        }

        struct dirent *entry;
        while ((entry = readdir(dir))) {
                if (entry->d_type == DT_LNK && strstr(entry->d_name, "pci")) {
                        char path[256];
                        snprintf(path, sizeof(path), "/sys/class/%s/device/vendor", entry->d_name);

                        FILE *file = fopen(path, "r");
                        if (!file) {
                                continue;
                        }

                        char vendor[5];
                        if (fgets(vendor, sizeof(vendor), file)) {
                                vendor[strlen(vendor) - 1] = '\0';
                                for (const char **name = hw_device_names; *name; ++name) {
                                        if (strstr(vendor, *name)) {
                                                fclose(file);
                                                closedir(dir);
                                                return true;
                                        }
                                }
                        }

                        fclose(file);
                }
        }

        closedir(dir);
        return false;
}


//////////////////////////////////////////////////////////////////
int main() {

        bool is_virtual = false;

        printf("rcDetectVirtual - TESTING FOR VIRTUALIZATION\n");
        printf("WARNING: Any of these tests can produce false positives\n");
        printf("##########################################################\n\n");


        printf("TESTING CPUID: ");
        if (check_cpuid()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using CPUID check.\n\n");
        }


        printf("TESTING INTERRUPT DESCRIPTOR TABLE: ");
        if (check_idt()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using IDT check.\n\n");
        }


        printf("TESTING PROCESS TABLE: ");
        if (check_process_list()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using Process Table Analysis.\n\n");
        }


        printf("TESTING MACHINE STATUS WORD: ");
        if (check_msw()) {
                is_virtual = true;
                printf("Virtualization detected.\n");
        }
        else {
                printf("No Virtualization detected using MSW check.\n\n");
        }


        printf("TESTING TIME STAMP COUNTER: ");
        if (check_tsc()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using TSC check.\n\n");
        }


        printf("TESTING SMBIOS: ");
        if (check_smbios()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using SMBIOS check.\n\n");
        }


        printf("CHECKING HARDWARE DEVICES WITH SYSFS: ");
        if (check_hw_devices()) {
                is_virtual = true;
                printf("Virtualization detected.\n\n");
        }
        else {
                printf("No Virtualization detected using SYSFS hardware check.\n\n");
        }

        if (!is_virtual) {
                printf("No virtualization detected.\n");
        }


    return 0;
}
