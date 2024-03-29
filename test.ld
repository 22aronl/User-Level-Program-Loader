MEMORY
{
    ram2 (rwx) : ORIGIN = 0x20000000, LENGTH = 1M
}

SECTIONS
{
    .text :
    {
        *(.text)
    } > ram2

    .data :
    {
        *(.data)
    } > ram2

    .bss :
    {
        *(.bss)
    } > ram2
}