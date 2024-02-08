#pragma once

#include "GPCS4Common.h"
#include "Emulator/Module.h"
#include "elf.h"

#include <cstdio>
#include <memory>
#include <vector>
#include <string>

struct SHeaderSelf
{
	char m_magic[4];     // Magic 4F 15 3D 1D
	char m_unknown0[4];  // Always 00 01 01 12
	char m_category;     // Category 1 on SELF, 4 on PUP Entry (probably SPP). See PS3/PS Vita Category
	char m_programType;  // Program Type First Half denotes version (anything between 0, oldest and F, newest), second Half denotes true type, 4 for Games, 5 for sce_module modules, 6 for Video Apps like Netflix, 8 for System/EX Apps/Executables, 9 for System/EX modules/dlls
	char m_padding0[2];
	char m_headerSize[2];
	char m_signatureSize[2];  // Metadata Size
	char m_fileSize[4];       // Size of SELF
	char m_padding1[4];
	char m_numberOfSegments[2];  // 1 Kernel, 2 SL and Secure Modules, 4 Kernel ELFs, 6 .selfs, 2 .sdll, 6 .sprx, 6 ShellCore, 6 eboot.bin, 2 sexe
	char m_unknown1[2];          // Always 0x22
	char m_padding2[4];
};

struct SSegStructureSelf
{
	uint64_t m_flags;
	uint64_t m_offsets;
	uint64_t m_encryptedCompressedSize;
	uint64_t m_decryptedDecompressedSize;
};

enum class ESegFlags : uint64_t
{
	SF_ORDR = 0x1,    // ordered?
	SF_ENCR = 0x2,    // encrypted
	SF_SIGN = 0x4,    // signed
	SF_DFLG = 0x8,    // deflated
	SF_BFLG = 0x800,  // block segment
};

struct SMemoryChrunk
{
	void*    m_pAddress;
	uint64_t m_size;
};

#define PSET_SELFMAG 0x1D3D154F

class ELFMapper
{
public:
	ELFMapper() = default;

	ELFMapper(ELFMapper const &) = delete;
	void operator=(ELFMapper const &) = delete;

	bool loadFile(std::string const &filePath, NativeModule *mod);
	bool validateHeader();
	bool parseSegmentHeaders();
	bool parseSelfSegmentHeaders();
	bool parseDynamicSection();
	bool mapImageIntoMemory();
	bool parseSymbols();

	void *getProcParam() const;

private:
	bool prepareTables(Elf64_Dyn const &entry, uint32_t index);
	bool parseSingleDynEntry(Elf64_Dyn const &entry, uint32_t index);
	size_t calculateTotalLoadableSize();
	bool isSegmentLoadable(Elf64_Phdr const &hdr);

	bool mapCodeSegment(Elf64_Phdr const &hdr);
	bool mapSecReloSegment(Elf64_Phdr const &phdr);
	bool mapDataSegment(Elf64_Phdr const &phdr);

	NativeModule *m_moduleData;
};
