ENTRY(_start)

TEXT_BASE = 0x1337;

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
}

SECTIONS
{
    . = SIZEOF_HEADERS;

    .pad :
    {
        BYTE(0);
        . = TEXT_BASE - SIZEOF_HEADERS;
    } :text

    .text TEXT_BASE : SUBALIGN(1)
    {
        KEEP(*(.text.start))
        *(.text)
        *(.text.*)
    } :text
}
