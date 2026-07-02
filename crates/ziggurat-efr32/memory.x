/* EFR32MG24A420F1536IM40 on the ZBT-2 — regions from the ZBT-2 build's linkerfile.ld.
 * The app lives above the Gecko bootloader (0x08000000..0x08006000); RAM's first 4 bytes
 * are the bootloader reset region. */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08006000, LENGTH = 0x178000
  RAM   (rwx) : ORIGIN = 0x20000004, LENGTH = 0x3fffc
}
