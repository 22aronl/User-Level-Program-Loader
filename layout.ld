MEMORY {
    loader_memory : ORIGIN = 0x10000000, LENGTH = 0x10000
    test_memory : ORIGIN = 0x20000000, LENGTH = 0x100000
}

SECTIONS {
    .loader :
    {
        loader.o (.text)
        loader.o (.data)
        loader.o (.bss)
    } > loader_memory

    .test :
    {
        test.o (.text)
        test.o (.data)
        test.o (.bss)
    } > test_memory
}