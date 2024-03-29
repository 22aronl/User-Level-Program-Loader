MEMORY
{
    ram (rwx) : ORIGIN = 0x10000000, LENGTH = 1M
}

SECTIONS
{
    .text :
    {
        *(.text)
    } > ram

    .data :
    {
        *(.data)
    } > ram

    .bss :
    {
        *(.bss)
    } > ram
}