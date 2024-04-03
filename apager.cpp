#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

//g++ -g -fpermissive -o apager apager.cpp magic.S -static -T layout.ld

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
    uint64_t* stack = (uint64_t*) &argv[argc];
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
    for (uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            // std::cerr << "Failed to read program header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if(phdr.p_type != PT_LOAD)
            continue;

        Elf64_Addr p_vaddr = phdr.p_vaddr;

        Elf64_Addr align = 0; // p_vaddr % page_size;

        // std::cout << "p_vaddr: " << std::hex << p_vaddr << std::endl;
        // uint64_t vaddr = (uint64_t)p_vaddr;
        // std::cout << "phoff: " << phoff + i * header.e_phentsize << " " << phdr.p_vaddr << " " << phdr.p_memsz << std::endl;
        // std::cout << "align" << phdr.p_align << " offset " << phdr.p_offset << " p_vaddr page " << (phdr.p_vaddr & ~(0x1000 - 1)) << std::endl;
        // std::cout << "mmap range" << std::hex << (phdr.p_vaddr & ~(0x1000 - 1)) << " " << (phdr.p_vaddr & ~(0x1000 - 1)) + phdr.p_memsz + (phdr.p_vaddr & (0x111)) << std::endl;

        if (phdr.p_vaddr == 0)
            continue;
        uint64_t high_address = (phdr.p_vaddr + phdr.p_memsz + (page_size - 1)) & ~(page_size - 1);
        void *segment_data = mmap((void *)(phdr.p_vaddr & ~(0x1000 - 1)), high_address - (phdr.p_vaddr & ~(0x1000 - 1)), PROT_WRITE | PROT_READ | PROT_EXEC,
                                  MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
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


    for (uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;

        int k = pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_phentsize);
        if (k != sizeof(phdr)) {
            printf("Failed to read program header\n");
            // std::cerr << "Failed to read program header" << std::endl;
            close(elf_fd);
            return -1;
        }

        if(phdr.p_type != PT_LOAD)
            continue;

        Elf64_Addr p_vaddr = phdr.p_vaddr;
        // if(phdr.p_filesz > 0) {
        //     std::cout << "phdr.p_filesz: " << phdr.p_filesz << std::endl;
        // std::cout << "segment_data: " << " " << "  " << phdr.p_vaddr << " " << phdr.p_memsz + phdr.p_align << " " << phdr.p_filesz
        //           << std::endl;
        //     std::cout << std::endl;
        //     // // Copy data from ELF file to memory

        if (pread(elf_fd, (void*) phdr.p_vaddr, phdr.p_filesz, phdr.p_offset) != phdr.p_filesz) {
            printf("Failed to read segment data\n");
            // std::cerr << "Failed to read segment data" << std::endl;
            close(elf_fd);
            return -1;
        }

        if(phdr.p_vaddr == 0)
            continue;
        void* segment_data = (void *)phdr.p_vaddr;
        // print out the first few bytes of the
        // char *array = (char *)segment_data;
        // for (int i = 0; i < 16; i++) {
        //     char c = array[i];
        //     std::cout << std::hex << (uint16_t)c << " ";
        //     // std::cout << std::hex << (int) array[i] << " ";
        // }

        // std::cout << std::endl;
        // void *segment_data_ = (void *)0x401650;
        // for (int i = 0; i < 16; i++) {
        //     std::cout << std::hex << (int)((char *)segment_data_)[i] << " ";
        // }
        // std::cout << std::endl;

        //     // // Zero out the rest of the memory
        // std::cout << "memset: " << phdr.p_vaddr + phdr.p_filesz << " " << phdr.p_memsz - phdr.p_filesz << std::endl;
        // memset((void *)(phdr.p_vaddr + phdr.p_filesz), 0, phdr.p_memsz - phdr.p_filesz);
        // memcpy(segment_data, (void *)(phdr.p_vaddr + phdr.p_filesz), phdr.p_filesz);
        // }

        // std::cout << std::endl;
        // // void *segment_data_ = (void *)0x401650;
        // for (int i = 0; i < 16; i++) {
        //     std::cout << std::hex << (int)((char *)segment_data_)[i] << " ";
        // }
        // std::cout << std::endl;

        // std::cout << std::endl;
    }

    // print out the first 16 bytes of the segment at 401650
    // void *segment_data = (void *)0x40e000;
    // for (int i = 0; i < 16; i++) {
    //     std::cout << std::hex << (int)((char *)segment_data)[i] << " ";
    // }
    // std::cout << std::endl;

    // std::cout << "header.e_entry: " << header.e_entry << std::endl;

    // stack = (uint64_t*) &argv[argc];
    // int envp_count = 0;
    // while (*(stack++) != 0)
    //     envp_count++;

    // printf("env count: %d\n", envp_count);

    // Elf64_auxv_t *auxv_start = (Elf64_auxv_t *)stack;
    // Elf64_auxv_t *auxv_null = auxv_start;
    // while (auxv_null->a_type != AT_NULL) {
    //     auxv_null++;
    // }
    // printf("aux count: %lu\n", auxv_null - auxv_start);
    // printf("----- end stack check -----\n");

    // // char **envp = environ;
    // Elf32_auxv_t *auxv;
    // int aux_size = 0;
    // while (*envp++ != NULL)
    //     aux_size++;
    // ; /* from stack diagram above: *envp = NULL marks end of envp */

    void *new_stack = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + 8 * 1024 * 1024 - sizeof(uint64_t) * (argc + 3 + envp_count) - sizeof(Elf64_auxv_t) * (auxv_null - auxv_start + 1);
    char **new_stack_ar = (char **)(new_stack);

    if (new_stack == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // std::cout << "new_stack: " << new_stack << std::endl;
    uint64_t argc_ = argc;
    uint64_t* stack_top = (uint64_t *)new_stack;
    *(stack_top++) = argc;

    // new_stack_ar[0] = (char *)argc_;
    for (int i = 0; i < argc; i++) {
        *(stack_top++) = (uint64_t) argv[i];
    }
    // new_stack_ar[argc + 1] = NULL;
    *(stack_top++) = 0;

    for (int i = 0; i < envp_count; i++) {
        // new_stack_ar[argc + 2 + i] = envp[i];
        *(stack_top++) = (uint64_t)envp[i];
    }

    // new_stack_ar[envp_count + 3] = NULL;
    *(stack_top++) = 0;
    Elf64_auxv_t *auxv_stack = (Elf64_auxv_t *) stack_top;
    for(int i = 0; i < auxv_null - auxv_start; i++) {
        (*(auxv_stack)).a_type = auxv_start[i].a_type;
        (*(auxv_stack++)).a_un.a_val = auxv_start[i].a_un.a_val;
    }
    *(auxv_stack) = (Elf64_auxv_t){AT_NULL, 0};
    // for(int i = 0; i < auxv_null - auxv_start; i+=2) {
    //     new_stack_ar[argc + envp_count + 4 + i] = (char *)auxv_start[i].a_type;
    //     new_stack_ar[argc + envp_count + 4 + i + 1] = (char *)auxv_start[i].a_un.a_val;
    // }

    // new_stack_ar[argc + envp_count + 4 + (auxv_null - auxv_start) * 2] = NULL;

    // stack_check((uint64_t *)new_stack, argc, argv);

    // for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
    // /* auxv->a_type = AT_NULL marks the end of auxv */
    // {
    //     std::cout << "auxv->a_type: " << auxv->a_type << std::endl;
    //     if (auxv->a_type == AT_SYSINFO)
    //         printf("AT_SYSINFO is: 0x%x\n", auxv->a_un.a_val);
    // }

    // Now envp points to the null terminator of the environ array

    // // Next, move back to find the aux vector terminator which is 2 NULL pointers
    // // unsigned long *auxv = (unsigned long *)(envp + 1);
    // while (*auxv != 0 || *(auxv + 1) != 0) {
    //     auxv++;
    // }

    // // Determine the size of the auxiliary vector
    // int size = 0;
    // while (*(auxv + size) != 0) {
    //     size++;
    // }

    // std::cout << "size: " << 0 << std::endl;

    uint64_t entry = (uint64_t)header.e_entry;

    void *entry_point = (void *)entry;
    // ((void (*)())entry_point)();

    switch_elf(entry, new_stack);
    // jump to entry point
    // asm volatile("jmp *%0" : : "r"(entry));
}