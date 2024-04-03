#include <assert.h>
#include <csignal>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

// g++ -fpermissive -o hpager3 hpager3.cpp magic.S -static -T layout.ld

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

std::set<uint64_t> *segfault_addresses;

void signalHandler(int signum, siginfo_t *info, void *context) {
    // std::cerr << "Segmentation fault (signal " << signum << ") occurred." << std::endl;
    // std::cerr << "Address: " << info->si_addr << std::endl;
    uint64_t page_size = getpagesize();
    uint64_t page_start = (uint64_t)info->si_addr & ~(page_size - 1);
    if (mmap((void *)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    // std::cerr << "mmap range1 " << std::hex << page_start << " " << page_start + page_size << std::endl;
    segfault_addresses->insert(page_start);
    // std::cerr << "mmap range3 " << std::hex << page_start << " " << page_start + page_size << std::endl;
    page_start += page_size;
    // std::cerr << "Address: " << info->si_addr << std::endl;

    if (segfault_addresses->find(page_start) == segfault_addresses->end()) {
        // std::cerr << "mmap range2 " << std::hex << page_start << " " << page_start + page_size << std::endl;
        void *segment_data = mmap((void *)page_start, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        // std::cerr << "segment data " << segment_data << std::endl;
        if (segment_data == MAP_FAILED) {
            std::cerr << "Failed to allocate memory for segment" << std::endl;
            perror("mmap");
            exit(EXIT_FAILURE);
        }
        segfault_addresses->insert(page_start);
        segfault_addresses->insert(page_start + page_size);
    }

    // exit(signum);
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
    // printf("aux count: %lu\n", auxv_null - auxv_start);
    // printf("----- end stack check -----\n");

    // if (argc != 2) {
    //     printf("Usage: %s <file>\n", argv[0]);
    //     // std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
    //     return -1;
    // }
    struct sigaction sa;
    sa.sa_sigaction = signalHandler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);

    segfault_addresses = new std::set<uint64_t>();

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

        if (phdr.p_type != PT_LOAD)
            continue;

        Elf64_Addr p_vaddr = phdr.p_vaddr;

        Elf64_Addr align = 0; // p_vaddr % page_size;

        // std::cout << "p_vaddr: " << std::hex << p_vaddr << std::endl;
        // uint64_t vaddr = (uint64_t)p_vaddr;
        // std::cout << "phoff: " << phoff + i * header.e_phentsize << " " << phdr.p_vaddr << " " << phdr.p_memsz << std::endl;
        // std::cout << "align" << phdr.p_align << " offset " << phdr.p_offset << " p_vaddr page " << (phdr.p_vaddr & ~(0x1000 - 1)) << std::endl;

        if (phdr.p_type != PT_LOAD)
            continue;
        if (phdr.p_vaddr == 0)
            continue;

        uint64_t start_addr = phdr.p_vaddr & ~(0x1000 - 1);
        uint64_t end_addr = (phdr.p_vaddr + phdr.p_memsz + (page_size - 1)) & ~(page_size - 1);
        // uint64_t end_addr = (phdr.p_filesz + start_addr) + page_size;
        segfault_addresses->insert(start_addr);
        // std::cout << "mmap range" << std::hex << (phdr.p_vaddr & ~(0x1000 - 1)) << " "
        //           << (phdr.p_vaddr & ~(0x1000 - 1)) + phdr.p_memsz + (phdr.p_vaddr & (0x111)) << std::endl;
        // std::cerr << "mmap range" << std::hex << start_addr << " " << end_addr << std::endl;
        void *segment_data = mmap((void *)(phdr.p_vaddr & ~(0x1000 - 1)), end_addr - start_addr, PROT_WRITE | PROT_READ | PROT_EXEC,
                                  MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
        // std::cout << "segment_data: " << segment_data << " " << end_addr << " " << phdr.p_vaddr + phdr.p_memsz << std::endl;
        if (segment_data == MAP_FAILED) {
            printf("Failed to allocate memory for segment\n");
            // print error code
            perror("mmap");
            // std::cerr << "Failed to allocate memory for segment" << std::endl;
            close(elf_fd);
            return -1;
        }

        // Elf64_Addr p_vaddr = phdr.p_vaddr;

        if (pread(elf_fd, (void *)phdr.p_vaddr, phdr.p_filesz, phdr.p_offset) != phdr.p_filesz) {
            printf("Failed to read segment data\n");
            // std::cerr << "Failed to read segment data" << std::endl;
            close(elf_fd);
            return -1;
        }
    }

    void *new_stack = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + 8 * 1024 * 1024 -
                      sizeof(uint64_t) * (argc + 3 + envp_count) - sizeof(Elf64_auxv_t) * (auxv_null - auxv_start + 1);
    char **new_stack_ar = (char **)(new_stack);

    if (new_stack == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

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
        (*(auxv_stack++)).a_un.a_val = auxv_start[i].a_un.a_val;
    }
    *(auxv_stack) = (Elf64_auxv_t){AT_NULL, 0};

    // stack_check((uint64_t *)new_stack, argc, argv);

    // int i = 0;
    // while (envp[i] != NULL) {
    //     printf("envp[%d]: %s\n", i, envp[i]);
    //     i++;
    // }

    uint64_t entry = (uint64_t)header.e_entry;

    void *entry_point = (void *)entry;

    switch_elf(entry, new_stack);
}