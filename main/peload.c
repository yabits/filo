
#include <libpayload.h>
#include <config.h>
#include <timer.h>
#include <sys_info.h>
#include <pe.h>
/*
#include <pe_boot.h>
*/
#include <ipchecksum.h>
#include <fs.h>
#define DEBUG_THIS CONFIG_DEBUG_EFIBOOT
#include <debug.h>

extern unsigned int start_elf(unsigned long entry_point, unsigned long param);
extern char _start, _end;

static int check_mem_ranges(IMAGE_FILE_HEADER *fhdr)
{
    int i, j;
    unsigned long start, end;
    unsigned long prog_start, prog_end;
    struct memrange *mem;
    struct sysinfo_t *info = &lib_sysinfo;
    IMAGE_SECTION_HEADER sechdr;

    prog_start = virt_to_phys(&_start);
    prog_end = virt_to_phys(&_end);

    for (i = 0; i < fhdr->NumberOfSections; i++) {
        if (file_read(&sechdr, sizeof(sechdr)) != sizeof(sechdr)) {
            goto cannot_read;
        }
        /* TODO: Skip some section by flags */
        start = sechdr.Misc.PhysicalAddress;
        end = sechdr.Misc.PhysicalAddress + sechdr.SizeOfRawData;
        if (start < prog_start && end > prog_start)
            goto conflict;
        if (start < prog_end && end > prog_end)
            goto conflict;
        for (j = 0; j < info->n_memranges; j++) {
            mem = &info->memrange[j];
            if (mem->base <= start && mem->base + mem->size >= end)
                break;
        }
        if (j >= info->n_memranges)
            goto badseg;
    }
    return 1;

cannot_read:
    debug("Can't read PE section\n");
    return 0;

conflict:
    printf("%s occupies [%#lx-%#lx]\n", program_name, prog_start, prog_end);
badseg:
    printf("Section %d [%#lx-%#lx] doesn't fit into memory\n", i, start, end-1);
    return 0;
}

static int load_sections(IMAGE_FILE_HEADER *fhdr)
{
    int i;
    IMAGE_SECTION_HEADER sechdr;

    for (i=0; i<fhdr->NumberOfSections; i++) {
        if (file_read(&sechdr, sizeof(sechdr)) != sizeof(sechdr)) {
            debug("Can't read PE section\n");
            return LOADER_NOT_SUPPORT;
        }
        if (!sechdr.SizeOfRawData)
            continue;
        debug("loading... ");
        memcpy((char *)sechdr.VirtualAddress,
                    (void *)sechdr.PointerToRawData, sechdr.SizeOfRawData);
        if (sechdr.SizeOfRawData < sechdr.Misc.VirtualSize) {
            memset((char *)sechdr.VirtualAddress+sechdr.SizeOfRawData, 0,
                    sechdr.VirtualAddress - sechdr.SizeOfRawData);
        }
        debug("ok\n");
    }

    return 1;
}

int pe_load(const char *filename, const char *cmdline)
{
    IMAGE_DOS_HEADER doshdr;
    IMAGE_NT_HEADERS nthdr;
    IMAGE_FILE_HEADER *fhdr = NULL;
    IMAGE_OPTIONAL_HEADER *opthdr = NULL;
    int retval = 0;
    int image_retval = 0;
    int i;

    if (!file_open(filename))
        goto out;

    if (file_read(&doshdr, sizeof(doshdr)) != sizeof(doshdr)) {
        debug("Can't read DOS header\n");
        retval = LOADER_NOT_SUPPORT;
        goto out;
    }

    if (doshdr.e_magic != MAGIC_MZ) {
        debug("No DOS header\n");
        debug("e_magic: 0x%02x\n", doshdr.e_magic);
        retval = LOADER_NOT_SUPPORT;
        goto out;
    }

    file_seek(doshdr.e_lfanew);
    if (file_read(&nthdr, sizeof(nthdr)) != sizeof(nthdr)) {
        debug("Can't read NT header\n");
        retval = LOADER_NOT_SUPPORT;
        goto out;
    }

    if (nthdr.Signature != MAGIC_PE) {
        debug("No NT header\n");
        retval = LOADER_NOT_SUPPORT;
        goto out;
    }

    fhdr = &nthdr.FileHeader;
    if (!(fhdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        printf("Not an executable PE image\n");
        retval = LOADER_NOT_SUPPORT;
        goto out;
    }
    if (!check_mem_ranges(fhdr))
        goto out;

    file_seek(doshdr.e_lfanew + sizeof(IMAGE_NT_HEADERS));
    if (!load_sections(fhdr))
        goto out;

    /* TODO: Add Checksum */

    /* TODO boot_notes */

    /*
#if CONFIG_PCMCIA_CF
    cf_bar = phys_to_virt(pci_read_config32(PCI_DEV(0, 0xa, 1), 0x10));
    for( i = 0x836 ; i < 0x840 ; i++){
        cf_bar[i] = 0;
    }
#endif
    */

    opthdr = &nthdr.OptionalHeader;

    debug("current time: %lu\n", currticks());

    debug("AddressOfEntryPoint: %#x\n",
                        opthdr->AddressOfEntryPoint);
    printf("Jumping to entry point...\n");
    image_retval = start_elf(opthdr->ImageBase+opthdr->AddressOfEntryPoint, NULL);

    console_init();
    printf("Image returned with return value %#x\n", image_retval);
    retval = 0;

out:
    file_close();
    return retval;
}

