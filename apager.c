// #include <iostream>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char* argv []) {

    if(argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        // std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
        return -1;
    }

    int elf_fd = open(argv[1], O_RDONLY);
    if(elf_fd == -1) {
        printf("Failed to open file: %s\n", argv[1]);
        // std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return -1;
    }

    Elf64_Ehdr header;
    if(read(elf_fd, &header, sizeof(header)) != sizeof(header)) {
        printf("Failed to read ELF header\n");
        // std::cerr << "Failed to read ELF header" << std::endl;
        close(elf_fd);
        return -1;
    }

    if(header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 ||
       header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3) {
        printf("Invalid ELF magic\n");
        // std::cerr << "Invalid ELF magic" << std::endl;
        close(elf_fd);
        return -1;
    }

    if(header.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit ELF files are supported\n");
        // std::cerr << "Only 64-bit ELF files are supported" << std::endl;
        close(elf_fd);
        return -1;
    }

    //assume elf header is set up properly now

    uint64_t phoff = header.e_phoff;
    for(uint64_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr phdr;
        pread(elf_fd, &phdr, sizeof(phdr), phoff + i * header.e_ehsize);
    

        void* segment_data = mmap((void*) phdr.p_vaddr, phdr.p_memsz, PROT_WRITE | PROT_READ | PROT_EXEC,
                                  MAP_POPULATE, -1, 0);
        if (segment_data == MAP_FAILED) {
            printf("Failed to allocate memory for segment\n");
            // std::cerr << "Failed to allocate memory for segment" << std::endl;
            close(elf_fd);
            return -1;
        }

        // Copy data from ELF file to memory
        memcpy(segment_data, (void*) (phdr.p_vaddr + phdr.p_filesz), phdr.p_filesz);
    }

    void* entry = (void*) header.e_entry;
    
    //jump to entry point
    asm volatile("jmp *%0" : : "r"(entry));
}