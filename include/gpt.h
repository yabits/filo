#ifndef GPT_H
#define GPT_H

typedef struct _guid {
        unsigned long Data1;
        unsigned short Data2;
        unsigned short Data3;
        unsigned char Data4[8];
} guid;

/* Protective MBR */
struct protective_mbr {
        unsigned char boot;
        unsigned char head;
        unsigned char sector;
        unsigned char cyl;
        unsigned char type;
        unsigned char e_head;
        unsigned char e_sector;
        unsigned char e_cyl;
        unsigned char start_sect[4];    /* unaligned little endian */
        unsigned char nr_sects[4];      /* ditto */
} *mbrp;

/* GPT Header */
struct gpt_header {
        uint64_t Signature;
        uint32_t Revision;
        uint32_t HeaderSize;
        uint32_t HeaderCRC32;
        uint32_t Reserved0;
        uint64_t myLBA;
        uint64_t AlternateLBA;
        uint64_t FirstUsableLBA;
        uint64_t LastUsableLBA;
        guid     DiskGUID;
        uint64_t PartitionEntryLBA;     
        uint32_t NumberOfPartitionEntries;
        uint32_t SizeOfPartitionEntry;
        uint32_t PartitionEntryArrayCRC32;
        uint8_t  Reserved1[DEV_SECTOR_SIZE-92];
} *gptp;

/* GPT Entry */
struct gpt_entry {
        guid PartitionTypeGUID;
        guid UniquePartitionGUID;
        uint64_t StartingLBA;
        uint64_t EndingLBA;
        uint64_t Attributes;
        uint8_t PartitionName[9];
        /* We assume SizeOfPartitionEntry is 128 */
        /* uint8_t reserved[DEV_SECTOR_SIZE-128]; */
} *gptep;

#endif /* GPT_H */
