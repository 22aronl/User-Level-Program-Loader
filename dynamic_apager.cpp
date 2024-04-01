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
#include <sys/auxv.h>

// g++ -g -fpermissive -o dapager dynamic_apager.cpp magic.S -T layout.ld

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

    int envp_counter = 0;
    while (envp[envp_counter] != NULL) {
        printf("envp[%d]: %s\n", envp_counter, envp[envp_counter]);
        envp_counter++;
    }

    // envp_count = envp_counter;
    // printf("aux count: %lu\n", auxv_null - auxv_start);
    // printf("----- end stack check -----\n");

    // if (argc != 2) {
    //     printf("Usage: %s <file>\n", argv[0]);
    //     // std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
    //     return -1;
    // }

    int elf_fd = open(argv[1], O_RDONLY);
    if (elf_fd == -1) {
        printf("Failed to open file: %s\n", argv[1]);
        // std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return -1;
    }

    Elf64_Ehdr header;
    if (pread(elf_fd, &header, sizeof(header), 0) != sizeof(header)) {
        printf("Failed to read ELF header\n");
        // std::cerr << "Failed to read ELF header" << std::endl;
        close(elf_fd);
        return -1;
    }

    if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 || header.e_ident[EI_MAG2] != ELFMAG2 ||
        header.e_ident[EI_MAG3] != ELFMAG3) {
        printf("Invalid ELF magic\n");
        // std::cerr << "Invalid ELF magic" << std::endl;
        close(elf_fd);
        return -1;
    }

    if (header.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit ELF files are supported\n");
        // std::cerr << "Only 64-bit ELF files are supported" << std::endl;
        close(elf_fd);
        return -1;
    }

    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    // printf("Page size: %ld bytes\n", page_size);

    // assume elf header is set up properly now

    uint64_t phoff = header.e_phoff;
    bool has_dynamic = false;
    int dynamic_idx = -1;
    for (uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            // std::cerr << "Failed to read program header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if (phdr.p_type == PT_LOAD || phdr.p_type == PT_DYNAMIC || phdr.p_type == PT_INTERP || phdr.p_type == PT_PHDR) {

            Elf64_Addr p_vaddr = phdr.p_vaddr;

            Elf64_Addr align = 0; // p_vaddr % page_size;

            // std::cout << "p_vaddr: " << std::hex << p_vaddr << std::endl;
            // uint64_t vaddr = (uint64_t)p_vaddr;
            // std::cout << "phoff: " << phoff + i * header.e_phentsize << " " << phdr.p_vaddr << " " << phdr.p_memsz << std::endl;
            // std::cout << "align" << phdr.p_align << " offset " << phdr.p_offset << " p_vaddr page " << (phdr.p_vaddr & ~(0x1000 - 1)) << std::endl;
            // std::cout << "mmap range " << std::hex << (phdr.p_vaddr & ~(0x1000 - 1)) << " "
                    //   << ((phdr.p_memsz + phdr.p_vaddr) & ~(0x1000 - 1)) + page_size << std::endl;

            if (phdr.p_vaddr == 0)
                continue;
            void *segment_data = mmap((void *)(phdr.p_vaddr & ~(0x1000 - 1)), ((phdr.p_memsz + phdr.p_vaddr) & ~(0x1000 - 1)) + page_size,
                                      PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
            // std::cout << "segment_data: " << segment_data << std::endl;
            if (segment_data == MAP_FAILED) {
                printf("Failed to allocate memory for segment\n");
                // print error code
                perror("mmap");
                // std::cerr << "Failed to allocate memory for segment" << std::endl;
                close(elf_fd);
                return -1;
            }
        }
        // } else if (phdr.p_type == PT_DYNAMIC) {
        //     has_dynamic = true;
        //     dynamic_idx = i;
        // }
    }

    for (int i = 0; i < header.e_shnum; i++) {
        Elf64_Shdr shdr;
        int k = pread(elf_fd, &shdr, sizeof(shdr), header.e_shoff + i * header.e_shentsize);
        if (k != sizeof(shdr)) {
            printf("Failed to read section header\n");
            // std::cerr << "Failed to read section header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if (shdr.sh_type == SHT_NULL)
            continue;

        // std::cerr << "section name: " << shdr.sh_name << std::endl;
        // std::cerr << "section addr: " << std::hex << shdr.sh_addr << std::endl;
        // std::cerr << "section size: " << shdr.sh_size << std::endl;
        // std::cerr << "section type: " << shdr.sh_type << std::endl;

        uint64_t start = shdr.sh_addr & ~(0x1000 - 1);
        uint64_t end = (shdr.sh_addr) + ((shdr.sh_size) & ~(0x1000 - 1)) + page_size;
        // std::cerr << "section start: " << std::hex << start << std::endl;
        // std::cerr << "section end: " << std::hex << end << std::endl;
        // std::cerr << std::endl;

        if (start == 0)
            continue;

        void *section_data = mmap((void *)start, end - start, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
        if (section_data == MAP_FAILED) {
            printf("Failed to allocate memory for section\n");
            // std::cerr << "Failed to allocate memory for section" << std::endl;
            perror("mmap");
            close(elf_fd);
            return -1;
        }
    }

    uint64_t interp_loc = -1;
    uint64_t phdr_loc = -1;

    for (uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            // std::cerr << "Failed to read program header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if ((phdr.p_type == PT_LOAD || phdr.p_type == PT_DYNAMIC || phdr.p_type == PT_INTERP || phdr.p_type == PT_PHDR)) {

            if(phdr.p_type == PT_INTERP) {
                interp_loc = phdr.p_vaddr;
            }

            if(phdr.p_type == PT_PHDR) {
                phdr_loc = phdr.p_vaddr;
            }

            Elf64_Addr p_vaddr = phdr.p_vaddr;

            if (pread(elf_fd, (void *)phdr.p_vaddr, phdr.p_filesz, phdr.p_offset) != phdr.p_filesz) {
                printf("Failed to read segment data\n");
                // std::cerr << "Failed to read segment data" << std::endl;
                close(elf_fd);
                return -1;
            }

            if (phdr.p_vaddr == 0)
                continue;
        }
    }

    for (int i = 0; i < header.e_shnum; i++) {
        Elf64_Shdr shdr;
        int k = pread(elf_fd, &shdr, sizeof(shdr), header.e_shoff + i * header.e_shentsize);
        if (k != sizeof(shdr)) {
            printf("Failed to read section header\n");
            // std::cerr << "Failed to read section header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if (shdr.sh_type == SHT_NULL)
            continue;

        // std::cerr << "section name: " << shdr.sh_name << std::endl;
        // std::cerr << "section addr: " << std::hex << shdr.sh_addr << std::endl;
        // std::cerr << "section size: " << shdr.sh_size << std::endl;
        // std::cerr << "section type: " << shdr.sh_type << std::endl;

        uint64_t start = shdr.sh_addr & ~(0x1000 - 1);
        uint64_t end = (shdr.sh_addr) + ((shdr.sh_size) & ~(0x1000 - 1)) + page_size;
        // std::cerr << "section start: " << std::hex << start << std::endl;
        // std::cerr << "section end: " << std::hex << end << std::endl;
        // std::cerr << std::endl;

        if (start == 0)
            continue;

        if (pread(elf_fd, (void *)shdr.sh_addr, shdr.sh_size, shdr.sh_offset) != shdr.sh_size) {
            printf("Failed to read section data\n");
            // std::cerr << "Failed to read section data" << std::endl;
            close(elf_fd);
            return -1;
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

    // std::cout << "new_stack: " << new_stack << std::endl;
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

        // if(auxv_start[i].a_type == AT_PHDR) {
        //     (*(auxv_stack)).a_un.a_val = phdr_loc;
        //     std::cerr << std::hex << auxv_start[i].a_type << "phdr_loc: " << phdr_loc << std::endl;
        // }

        // if(auxv_start[i].a_type == AT_PHNUM) {
        //     (*(auxv_stack)).a_un.a_val = header.e_phnum;
        // }

        // if(auxv_start[i].a_type == AT_ENTRY) {
        //     (*(auxv_stack)).a_un.a_val = header.e_entry;
        //     std::cerr << std::hex  << "entry: " << header.e_entry << std::endl;
        // }
        (*(auxv_stack++));
    }
    *(auxv_stack) = (Elf64_auxv_t){AT_NULL, 0};
    stack_check((uint64_t *)new_stack, argc, argv);

    // printf("Loaded ELF file\n");
    // // if the system has a dynamic
    if (has_dynamic) {
        // parse the symbol table to .dynsym

        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + dynamic_idx * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            // std::cerr << "Failed to read program header" << std::endl;
            close(elf_fd);
            return -1;
        }

        printf("Dynamic segment\n");

        if (phdr.p_type != PT_DYNAMIC) {
            printf("Invalid dynamic segment\n");
            // std::cerr << "Invalid dynamic segment" << std::endl;
            close(elf_fd);
            return -1;
        }

        uint64_t dt_strtab = 0;
        uint64_t dt_needed = 0;

        Elf64_Dyn dyn;
        if (pread(elf_fd, &dyn, sizeof(dyn), phdr.p_offset) != sizeof(dyn)) {
            printf("Failed to read dynamic segment\n");
            // std::cerr << "Failed to read dynamic segment" << std::endl;
            close(elf_fd);
            return -1;
        }

        printf("Dynamic segment2\n");

        int dyn_cur = 0;
        while (dyn.d_tag != DT_NULL) {
            printf("Tag: %lu\n", dyn.d_tag);
            if (dyn.d_tag == DT_NEEDED) {
                dt_needed = dyn.d_un.d_val;
                // char *str = (char *)dyn.d_un.d_val;
                // printf("Needed: %s\n", str);
            }

            if (dyn.d_tag == DT_STRTAB) {
                dt_strtab = dyn.d_un.d_ptr;
            }

            // increment dyn
            if (pread(elf_fd, &dyn, sizeof(dyn), phdr.p_offset + ++dyn_cur * sizeof(dyn)) != sizeof(dyn)) {
                printf("Failed to read dynamic segment\n");
                // std::cerr << "Failed to read dynamic segment" << std::endl;
                close(elf_fd);
                return -1;
            }
        }
        std::cerr << (dyn_cur) << std::endl;
        std::cerr << "dt_needed: " << dt_needed << std::endl;
        std::cerr << "dt_strtab: " << dt_strtab << std::endl;
        std::cerr << (char *)(dt_strtab + dt_needed) << std::endl;

        void *handle = dlopen((char *)(dt_strtab + dt_needed), RTLD_NOW);
        if (handle == NULL) {
            std::cerr << "dlopen failed" << std::endl;
            std::cerr << dlerror() << std::endl;
            return -1;
        } else {
            std::cerr << "dlopen success" << handle << std::endl;
        }
    }
    // uintptr_t entry_points = getauxval(AT_ENTRY);
    // std::cout << "entry point: " << entry_points << std::endl;

    //print out all auxvals on the stack
    auxv_stack = (Elf64_auxv_t *)stack_top;
    for(Elf64_auxv_t *auxv = auxv_stack; auxv->a_type != AT_NULL; auxv++) {
        // std::cout << "type: " << auxv->a_type << " value: " << auxv->a_un.a_val << std::endl;
        std::cerr << std::hex << "type: " << auxv->a_type << " value: " << auxv->a_un.a_val << std::endl;
        // (*(auxv)).a_un.a_val = auxv->a_un.a_val;
        // (*(auxv_stack++));
    }

    // std::cout << "size: " << 0 << std::endl;

    uint64_t entry = (uint64_t)header.e_entry;

    void *entry_point = (void *)entry;
    // std::cout << "entry point: " << entry_point << std::endl;
    if(interp_loc == -1) {
        switch_elf(entry, new_stack);
    } else {
        std::cerr << "interp " << (char*)interp_loc << std::endl;
        void *handle = dlopen((char *)(interp_loc), RTLD_NOW);
        std::cerr << "handle: " << handle << std::endl;
        //call handle as if it were a method
        void (*entry_point)(char*) = (void (*)(char*))dlsym(handle, "main");
        
        // handle(argv[1]);
        // switch_elf((uint64_t)handle, new_stack);
    }
}