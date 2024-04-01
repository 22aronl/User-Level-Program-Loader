#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

struct DynamicTags {
    uint64_t dynamic_tags[36] = {0}; // dyanmi tags, only up to 0-> 35
};

struct DynamicStruct {
    DynamicTags tags;
    uint64_t base_address;
};

struct LoadInfo {
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t offset;
    LoadInfo(uint64_t vaddr, uint64_t filesz, uint64_t memsz, uint64_t offset) : vaddr(vaddr), filesz(filesz), memsz(memsz), offset(offset) {}
};

struct LoadList {
    std::vector<LoadInfo> load_list;
    Elf64_Phdr header;
    uint64_t base_address{0};
    bool is_dynamic{false};
    uint64_t entry_pt{0};
    DynamicTags dynamic_tags;
};

// g++ -g -fpermissive -o dapager dynamic_apager2.cpp magic.S -T layout.ld

extern "C" void switch_elf(uint64_t entry, void *stack);
// extern char** environ;

/**
 * Routine for checking stack made for child program.
 * top_of_stack: stack pointer that will given to child program as %rsp
 * argc: Expected number of arguments
 * argv: Expected argument strings
 */
void stack_check(uint64_t *top_of_stack, uint64_t argc, char **argv) {
    printf("----- stack check -----\n");

    assert(((uint64_t)top_of_stack) % 8 == 0);
    printf("top of stack is 8-byte aligned\n");

    uint64_t *stack = top_of_stack;
    uint64_t actual_argc = *(stack++);
    printf("argc: %lu\n", actual_argc);
    assert(actual_argc == argc);

    for (int i = 0; i < argc; i++) {
        char *argp = (char *)*(stack++);
        assert(strcmp(argp, argv[i]) == 0);
        printf("arg %d: %s\n", i, argp);
    }
    // Argument list ends with null pointer
    assert(*(stack++) == 0);

    int envp_count = 0;
    while (*(stack++) != 0)
        envp_count++;

    printf("env count: %d\n", envp_count);

    Elf64_auxv_t *auxv_start = (Elf64_auxv_t *)stack;
    Elf64_auxv_t *auxv_null = auxv_start;
    while (auxv_null->a_type != AT_NULL) {
        auxv_null++;
    }
    printf("aux count: %lu\n", auxv_null - auxv_start);
    printf("----- end stack check -----\n");
}

DynamicStruct elf_dynamic(Elf64_Phdr phdr, int elf_fd) {
    DynamicStruct dynamic_struct;
    DynamicTags tags;
    std::vector<Elf64_Dyn> dyns;
    Elf64_Dyn dyn;

    if (pread(elf_fd, &dyn, sizeof(dyn), phdr.p_offset) != sizeof(dyn)) {
        printf("Failed to read dynamic segment\n");
        // std::cerr << "Failed to read dynamic segment" << std::endl;
        close(elf_fd);
        return {};
    }

    int dyn_cur = 0;
    while (dyn.d_tag != DT_NULL) {

        if (dyn.d_tag == DT_NEEDED || dyn.d_tag == DT_SONAME) {
            dyns.push_back(dyn);
        } else if (dyn.d_tag < 36) {
            tags.dynamic_tags[dyn.d_tag] = dyn.d_un.d_val;
        }

        // increment dyn
        if (pread(elf_fd, &dyn, sizeof(dyn), phdr.p_offset + ++dyn_cur * sizeof(dyn)) != sizeof(dyn)) {
            printf("Failed to read dynamic segment\n");
            // std::cerr << "Failed to read dynamic segment" << std::endl;
            close(elf_fd);
            return {};
        }
    }

    dynamic_struct.tags = tags;

    for (auto dyn : dyns) {
        if (dyn.d_tag == DT_NEEDED) {
            char *str = (char *)tags.dynamic_tags[DT_STRTAB] + dyn.d_un.d_val;

            void *handle = dlopen(str, RTLD_NOW);
            // void* handle = NULL;

            if (handle == NULL) {
                std::cerr << ("Failed to load library: ") << str << std::endl;
                exit(EXIT_FAILURE);
            } else {
                printf("Libary loaded: %s\n", str);
                dynamic_struct.base_address = (uint64_t)handle;
                // TODO: might be issue with multiple libraries (just ignore for now)
            }
        }
    }

    return dynamic_struct;
}

LoadList elf_parse(int elf_fd) {
    LoadList load_list;

    // both references need to be the same
    Elf64_Ehdr header;
    if (pread(elf_fd, &header, sizeof(header), 0) != sizeof(header)) {
        printf("Failed to read ELF header\n");
        // std::cerr << "Failed to read ELF header" << std::endl;
        close(elf_fd);
        return {};
    }

    if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 || header.e_ident[EI_MAG2] != ELFMAG2 ||
        header.e_ident[EI_MAG3] != ELFMAG3) {
        printf("Invalid ELF magic\n");
        // std::cerr << "Invalid ELF magic" << std::endl;
        close(elf_fd);
        return {};
    }

    if (header.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit ELF files are supported\n");
        // std::cerr << "Only 64-bit ELF files are supported" << std::endl;
        close(elf_fd);
        return {};
    }

    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    uint64_t low_address = -1;
    uint64_t high_address = 0;

    uint64_t phoff = header.e_phoff;
    for (uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            close(elf_fd);
            return {};
        }

        if (phdr.p_type == PT_LOAD) {

            if (phdr.p_vaddr == 0)
                continue;

            if (low_address == -1 || phdr.p_vaddr < low_address) {
                low_address = phdr.p_vaddr;
            }

            if (phdr.p_vaddr + phdr.p_memsz > high_address) {
                high_address = phdr.p_vaddr + phdr.p_memsz;
            }

            load_list.load_list.push_back(LoadInfo(phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz, phdr.p_offset));
        } else if (phdr.p_type == PT_DYNAMIC) {

            if (header.e_type == ET_REL) {
                load_list.dynamic_tags = DynamicTags();
            }

            load_list.is_dynamic = true;
            load_list.header = phdr;
        }
    }

    if (header.e_type == ET_REL) {
        std::cerr << "Relocatable file" << std::endl;
        uint64_t size = high_address - low_address;
        void *new_base_address = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (new_base_address == MAP_FAILED) {
            perror("mmap");
            exit(EXIT_FAILURE);
        }

        if (munmap(new_base_address, size) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }

        load_list.base_address = (uint64_t)new_base_address - low_address;
    }
    // else {
    //     low_address &= ~(page_size - 1);
    //     high_address = (high_address + page_size - 1) & ~(page_size - 1);

    //     void *new_base_address =
    //         mmap((void *)low_address, high_address - low_address, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0,
    //         0);

    //     if (new_base_address == MAP_FAILED) {
    //         perror("mmap");
    //         exit(EXIT_FAILURE);
    //     }
    // }

    load_list.entry_pt = header.e_entry;

    return load_list;
}

int main(int argc, char *argv[], char *envp[]) {
    uint64_t *stack = (uint64_t *)&argv[argc];
    (stack++);
    int envp_count = 0;
    while (*(stack++) != 0)
        envp_count++;

    // printf("env count: %d\n", envp_count);

    Elf64_auxv_t *auxv_start = (Elf64_auxv_t *)stack;
    Elf64_auxv_t *auxv_null = auxv_start;
    while (auxv_null->a_type != AT_NULL) {
        auxv_null++;
    }

    int elf_fd = open(argv[1], O_RDONLY);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    LoadList load_list = elf_parse(elf_fd);

    for (int i = 0; i < load_list.load_list.size(); i++) {
        uint64_t vaddr = load_list.load_list[i].vaddr + load_list.base_address;

        uint64_t low_address = vaddr;
        uint64_t high_address = low_address + load_list.load_list[i].memsz;

        low_address &= ~(page_size - 1);
        high_address = (high_address + page_size - 1) & ~(page_size - 1);
        std::cerr << std::hex << "low_address: " << low_address << " high_address: " << high_address << std::endl;
        void *segment_data =
            mmap((void *)low_address, high_address - low_address, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (segment_data == MAP_FAILED) {
            std::cerr << "Failed to allocate memory for segment" << std::endl;
            perror("mmap");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < load_list.load_list.size(); i++) {
        uint64_t vaddr = load_list.load_list[i].vaddr + load_list.base_address;
        std::cerr << std::hex << "vaddr: " << vaddr << " filesz: " << load_list.load_list[i].filesz << " offset: " << load_list.load_list[i].offset
                  << std::endl;
        if (pread(elf_fd, (void *)vaddr, load_list.load_list[i].filesz, load_list.load_list[i].offset) != load_list.load_list[i].filesz) {
            std::cerr << "Failed to read segment data" << std::endl;
            perror("pread");
            exit(EXIT_FAILURE);
        }
    }

    // std::cout << "header type: " << header.e_type << std::endl;
    // std::cout << "header.e_entry: " << header.e_entry << std::endl;

    void *new_stack = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + 8 * 1024 * 1024 -
                      sizeof(uint64_t) * (argc + 3 + envp_count) - sizeof(Elf64_auxv_t) * (auxv_null - auxv_start + 1);
    char **new_stack_ar = (char **)(new_stack);

    if (new_stack == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    std::cerr << "new_stack: " << new_stack << std::endl;
    uint64_t argc_ = argc;
    uint64_t *stack_top = (uint64_t *)new_stack;
    *(stack_top++) = argc;

    // new_stack_ar[0] = (char *)argc_;
    for (int i = 0; i < argc; i++) {
        *(stack_top++) = (uint64_t)argv[i];
    }
    // new_stack_ar[argc + 1] = NULL;
    *(stack_top++) = 0;

    for (int i = 0; i < envp_count; i++) {
        // new_stack_ar[argc + 2 + i] = envp[i];
        *(stack_top++) = (uint64_t)envp[i];
    }

    // new_stack_ar[envp_count + 3] = NULL;
    *(stack_top++) = 0;
    Elf64_auxv_t *auxv_stack = (Elf64_auxv_t *)stack_top;
    for (int i = 0; i < auxv_null - auxv_start; i++) {
        (*(auxv_stack)).a_type = auxv_start[i].a_type;
        (*(auxv_stack)).a_un.a_val = auxv_start[i].a_un.a_val;
        if(auxv_start[i].a_type == AT_PHNUM) {
            (*(auxv_stack)).a_un.a_val = 10;
        }
        if(auxv_start[i].a_type == AT_BASE) {
            (*(auxv_stack)).a_un.a_val = 0;
        }
        (*(auxv_stack++));
    }
    *(auxv_stack) = (Elf64_auxv_t){AT_NULL, 0};
    stack_check((uint64_t *)new_stack, argc, argv);

    // printf("Loaded ELF file\n");
    // // if the system has a dynamic

    // uintptr_t entry_points = getauxval(AT_ENTRY);
    // std::cout << "entry point: " << entry_points << std::endl;

    // print out all auxvals on the stack
    auxv_stack = (Elf64_auxv_t *)stack_top;
    for (Elf64_auxv_t *auxv = auxv_stack; auxv->a_type != AT_NULL; auxv++) {
        // std::cout << "type: " << auxv->a_type << " value: " << auxv->a_un.a_val << std::endl;
        std::cerr << std::hex << "type: " << auxv->a_type << " value: " << auxv->a_un.a_val << std::endl;
        // (*(auxv)).a_un.a_val = auxv->a_un.a_val;
        // (*(auxv_stack++));
    }

    // std::cout << "size: " << 0 << std::endl;

    uint64_t entry = (uint64_t)load_list.entry_pt;

    void *entry_point = (void *)entry;
    std::cerr << "entry point: " << entry_point << std::endl;
    switch_elf(entry, new_stack);
}