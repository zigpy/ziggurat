/***************************************************************************//**
 * GCC Linker script for Silicon Labs devices
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 ******************************************************************************/

 MEMORY
 {
   FLASH      (rx)  : ORIGIN = 0x8000000, LENGTH = 0x17e000
   RAM        (rwx) : ORIGIN = 0x20000000, LENGTH = 0x40000
   /* Dummy region is used for the dummy segment, which in turn never gets data
    * loaded, but is only used to calculate the size of objects placed in it. */
   DUMMY      (!ax) : ORIGIN = 0xffe82000, LENGTH = 0x17e000
 }

/*******************************************************************************
 * Due to an issue in GNU LD, which results in wrongly applying the writeable
 * flag to a text section (thereby triggering an error since the memory block is
 * declared rx), we need to define our segments manually.
 *
 * Typical Silicon Labs program layout:
 *
 * ----- START OF APPLICATION FLASH -----
 * R   - Vector table
 * R X - RAM functions (copied to RAM at startup)
 * R   - Read-only data
 * R X - Code
 * R X - Secure Gateways (Trustzone S only)
 * R X - extab
 * R X - exidx
 * R   - startup copy table
 * R   - startup zeroization table
 * RW  - Initialised RAM data (copied to RAM at startup)
 *     - [unallocated space]
 *     - NVM (defined using linker symbols only, not an ELF section)
 * ----- END OF APPLICATION FLASH -----
 *
 * ----- START OF APPLICATION RAM -----
 * RW  - Bootloader reset reason (if present)
 * RW  - stack
 * RW  - stack sealing
 * RW  - BSS (zero-init RAM)
 * RW  - uninitialised RAM
 * R X - RAM functions
 * RW  - Initialised RAM
 * RW  - Heap (automatically expanded to end of RAM)
 * ----- END OF APPLICATION RAM -----
 *
 * ----- START OF DUMMY REGION -----
 * RW  - NVM sections (not loadable, only such that linker can calculate the size
 *       of the symbols placed inside it, to subtract that size from the end of
 *       the available flash space)
 * ----- END OF DUMMY REGION -----
 *
 * For the purpose of defining segments, we need a new segment whenever the
 * data loaded changes type. That means e.g. we need three segments for all RAM
 * content: the initial RW segment, the RX segment, and the final RW segment.
 ******************************************************************************/

PHDRS
{
  vectors PT_LOAD FLAGS(4);       /* Flash content before RAM functions is R */
  readonly PT_LOAD FLAGS(4);      /* Readonly content after RAM functions */
  text PT_LOAD FLAGS(5);          /* Executable flash content after readonly */
  tables PT_LOAD FLAGS(4);        /* Tables supporting startup copying are R */
  empty PT_LOAD FLAGS(4);         /* Empty area is R */

  ram_pre_code PT_LOAD FLAGS(6);  /* All RAM content before RAMfuncs is RW */
  ram_code PT_LOAD FLAGS(5);      /* RAMfuncs need to be RX */
  ram_data PT_LOAD FLAGS(6);      /* Relocatable RAM data needs own segment */
  ram_post_data PT_LOAD FLAGS(6); /* All RAM content after data is RW */

  dummy_seg PT_NULL FLAGS(4);     /* Dummy segment for dummy sections */
}

ENTRY(Reset_Handler)

SECTIONS
{
  .vectors :
  {
    linker_vectors_begin = .;
    KEEP(*(.vectors))
    linker_vectors_end = .;

    __Vectors_End = .;
    __Vectors_Size = __Vectors_End - __Vectors;
  } > FLASH :vectors

  .stack (NOLOAD):
  {
    . = ALIGN(8);
    __stack_limit = .;
    __StackLimit = .;
    KEEP(*(.stack*))
    . = ALIGN(4);
    __stack = .;
    __StackTop = .;
  } > RAM :ram_pre_code

  .bss :
  {
    . = ALIGN(4);
    __bss_start__ = .;
    *(SORT_BY_ALIGNMENT(.bss*))
    *(COMMON)
    . = ALIGN(4);
    __bss_end__ = .;
  } > RAM :ram_pre_code

  .noinit (NOLOAD) : ALIGN(4)
  {
    *(.noinit*);
  } > RAM :ram_pre_code

  text_application_ram : ALIGN(4)
  {
    . = ALIGN(4);
    __vma_ramfuncs_start__ = .;

    /* text_application_ram */
    *(text_application_ram)

    . = ALIGN(4);
    __vma_ramfuncs_end__ = .;
  } > RAM AT > FLASH :ram_code

  __lma_ramfuncs_start__ = LOADADDR(text_application_ram);
  __lma_ramfuncs_end__ = LOADADDR(text_application_ram) + SIZEOF(text_application_ram);

  .rodata :
  {
  } > FLASH :readonly

  .text :
  {
    linker_code_begin = .;
    *(SORT_BY_ALIGNMENT(.text*))
    *(SORT_BY_ALIGNMENT(text_*))
    . = ALIGN(32);
    linker_code_end = .;

    KEEP(*(.init))
    KEEP(*(.fini))

    /* .ctors */
    *crtbegin.o(.ctors)
    *crtbegin?.o(.ctors)
    *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
    *(SORT(.ctors.*))
    *(.ctors)

    /* .dtors */
    *crtbegin.o(.dtors)
    *crtbegin?.o(.dtors)
    *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
    *(SORT(.dtors.*))
    *(.dtors)

    *(.rodata*)
    *(.eh_frame*)
  } > FLASH :text

  .ARM.extab :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } > FLASH :text

  __exidx_start = .;
  .ARM.exidx :
  {
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } > FLASH :text
  __exidx_end = .;

  .copy.table :
  {
    . = ALIGN(4);
    __copy_table_start__ = .;

    LONG (__etext)
    LONG (__data_start__)
    LONG ((__data_end__ - __data_start__) / 4)

    /* Add each additional data section here */
    /*
    LONG (__etext2)
    LONG (__data2_start__)
    LONG ((__data2_end__ - __data2_start__) / 4)
    */

    __copy_table_end__ = .;
  } > FLASH :tables

  .zero.table :
  {
    . = ALIGN(4);
    __zero_table_start__ = .;
    /* Add each additional bss section here */
    /*
    LONG (__bss2_start__)
    LONG ((__bss2_end__ - __bss2_start__) / 4)
    */

    __zero_table_end__ = .;
  } > FLASH :tables

  .data :
  {
    *(vtable)
    *(SORT_BY_ALIGNMENT(.data*))
    . = ALIGN(4);

    . = ALIGN(4);
    /* preinit data */
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP(*(.preinit_array))
    PROVIDE_HIDDEN (__preinit_array_end = .);

    . = ALIGN(4);
    /* init data */
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP(*(SORT(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE_HIDDEN (__init_array_end = .);

    . = ALIGN(4);
    /* finit data */
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP(*(SORT(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE_HIDDEN (__fini_array_end = .);

    . = ALIGN(4);
    /* All data end */

  } > RAM AT > FLASH :ram_data

  /* Values to support copying initialised values at startup */
  __etext = LOADADDR(.data);
  __data_start__ = ADDR(.data);
  __data_end__ = ADDR(.data) + SIZEOF(.data);

  ASSERT((__etext % 4) == 0, "Data section needs to be word-aligned in LMA")
  ASSERT((__data_start__ % 4) == 0, "Data section needs to be word-aligned in VMA")
  ASSERT((__data_end__ % 4) == 0, "Data section needs to be word-multiple sized")
  /* Sets the difference between VMA and LMA to 0 for the next NOLOAD sections */
  .empty :
  {
  } > FLASH :empty

/* Calculate heap size based on RAM limits. */
heap_limit = ORIGIN(RAM) + LENGTH(RAM);  /* End of RAM */
heap_size = heap_limit - __HeapBase;
  .heap (NOLOAD):
  {
    . = ALIGN(8);
    __HeapBase = .;
    . += heap_size;
    __end__ = .;
    _end = __end__;
    KEEP(*(.heap*))
    __HeapLimit = ORIGIN(RAM) + LENGTH(RAM);
  } > RAM :ram_post_data

  __ram_end__ = 0x20000000 + 0x40000;
  __main_flash_end__ = 0x8000000 + 0x17e000;

   /* This is where we handle flash storage blocks. We use dummy sections for finding the configured
   * block sizes and then "place" them at the end of flash when the size is known. */
  .internal_storage (NOLOAD) : {
    KEEP(*(.internal_storage*))
  } > DUMMY :dummy_seg


  .nvm (NOLOAD) : {
    KEEP(*(.simee*))
  } > DUMMY :dummy_seg

  __ramfuncs_start__ = __vma_ramfuncs_start__;
  __ramfuncs_end__ = __vma_ramfuncs_end__;

  linker_nvm_end = __main_flash_end__;
  linker_nvm_begin = linker_nvm_end - SIZEOF(.nvm);
  linker_storage_end = linker_nvm_begin;
  __nvm3Base = linker_nvm_begin;

  linker_storage_begin = linker_storage_end - SIZEOF(.internal_storage);
  ASSERT((linker_storage_begin >= (__etext + SIZEOF(.data))), "FLASH memory overflowed !")


  HIDDEN(app_flash_end = 0x8000000 + 0x17e000);
  ASSERT( (linker_nvm_begin + SIZEOF(.nvm)) <= app_flash_end, "NVM3 is excessing the flash size !")

}
