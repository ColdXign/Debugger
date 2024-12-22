#include "pch.h"
#include "ViewPEHeader.h"

bool load_pe_headers()
{
        struct pe_struct* pe_headers = (struct pe_struct*)malloc(sizeof(struct pe_struct));

        pe_headers = load_file(&pe_headers);
        print_image_dos_headers(pe_headers->m_img_dos_header);
        pe_headers->m_img_nt_headers = (PIMAGE_NT_HEADERS)((DWORD64)pe_headers->m_img_dos_header + pe_headers->m_img_dos_header->e_lfanew);
        pe_headers->m_img_data_directory = &pe_headers->m_img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (0 != check_signature(pe_headers->m_img_nt_headers))
        {
                return false;
        }
        print_img_file_header(pe_headers->m_img_nt_headers);
        print_img_optional_headers(&pe_headers->m_img_nt_headers->OptionalHeader);
        print_img_section_table(&pe_headers->m_img_nt_headers->OptionalHeader, pe_headers->m_img_nt_headers->FileHeader.NumberOfSections);

        return true;
}

struct pe_struct* load_file(struct pe_struct** in_pe_headers)
{
        LPCWSTR file_name = L"C:\\PersonalProject\\TestGit\\Binary\\Target\\04-ProcessInfo.exe";
        (*in_pe_headers)->m_file = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD get_error = GetLastError();
        (*in_pe_headers)->m_file_mapping = CreateFileMappingW((*in_pe_headers)->m_file, NULL, PAGE_READONLY, 0, 0, NULL);
        DWORD dwfile_size = GetFileSize((*in_pe_headers)->m_file, NULL);
        LPVOID file_base = NULL;

        if (NULL != (*in_pe_headers)->m_file_mapping)
        {
                file_base = MapViewOfFile((*in_pe_headers)->m_file_mapping, FILE_MAP_READ, 0, 0, dwfile_size);
                (*in_pe_headers)->m_img_dos_header = (PIMAGE_DOS_HEADER)file_base;
        }
        //(*in_pe_headers)->m_img_import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(*in_pe_headers)->m_file_mapping + (*in_pe_headers)->m_img_data_directory->VirtualAddress;

        return (*in_pe_headers);
}

bool unload_file_pe(HANDLE in_hfile, HANDLE in_hfile_mapping, struct pe_struct* in_pe_headers)
{
        CloseHandle(in_hfile);
        CloseHandle(in_hfile_mapping);

        if (NULL != in_pe_headers)
        {
                free(in_pe_headers);
                in_pe_headers = NULL;
                return true;
        }
        return false;
}

void print_image_dos_headers(PIMAGE_DOS_HEADER in_img_dos_header)
{
        wprintf(L"IMAGE DOS HEADER\n");
        wprintf(L"====================================================================\n");
        wprintf(L"  e_magic    : %x   == Header Start MZ\n", in_img_dos_header->e_magic);
        wprintf(L"  e_cblp     : %x     == Bytes on last page of file\n", in_img_dos_header->e_cblp);
        wprintf(L"  e_cp       : %x      == Pages in file\n", in_img_dos_header->e_cp);
        wprintf(L"  e_crlc     : %x      == Relocations\n", in_img_dos_header->e_crlc);
        wprintf(L"  e_cparhdr  : %x      == Size of header in paragraphs\n", in_img_dos_header->e_cparhdr);
        wprintf(L"  e_minalloc : %x      == Minimum extra paragraphs needed\n", in_img_dos_header->e_minalloc);
        wprintf(L"  e_maxalloc : %x   == Maximum extra paragraphs needed\n", in_img_dos_header->e_maxalloc);
        wprintf(L"  e_ss       : %x      == Initial (relative) SS value\n", in_img_dos_header->e_ss);
        wprintf(L"  e_sp       : %x     == Initial SP value\n", in_img_dos_header->e_sp);
        wprintf(L"  e_csum     : %x      == Checksum\n", in_img_dos_header->e_csum);
        wprintf(L"  e_ip       : %x      == Initial IP value\n", in_img_dos_header->e_ip);
        wprintf(L"  e_cs       : %x      == Initial (relative) CS value\n", in_img_dos_header->e_cs);
        wprintf(L"  e_lfarlc   : %x     == File address of relocation table\n", in_img_dos_header->e_lfarlc);
        wprintf(L"  e_ovno     : %x      == Overlay number\n\n", in_img_dos_header->e_ovno);

        for (UINT i = 0; i < 4; ++i)
        {
                wprintf(L"  e_res[%d]   : %x      == Reserved words\n", i, in_img_dos_header->e_res[i]);
        }

        wprintf(L"\n  e_oemid    : %x      == OEM identifier (for e_oeminfo)\n", in_img_dos_header->e_oemid);
        wprintf(L"  e_oeminfo  : %x      == OEM information; e_oemid specific\n\n", in_img_dos_header->e_oeminfo);

        for (UINT i = 0; i < 10; ++i)
        {
                wprintf(L"  e_res2[%d]  : %x      == Reserved words\n", i, in_img_dos_header->e_res2[i]);
        }

        wprintf(L"\n  e_lfanew   : %x     == File address of new exe header*/\n\n", in_img_dos_header->e_lfanew);

        wprintf(L"====================================================================\n\n\n\n\n");
}

DWORD check_signature(PIMAGE_NT_HEADERS in_img_nt_headers)
{
        if (IMAGE_NT_SIGNATURE != in_img_nt_headers->Signature)
        {
                DWORD get_error;
                wprintf(L"It's not PE File Format!\n");
                get_error = GetLastError();
                wprintf(L"Error code : %d\n", get_error);
                return get_error;
        }

        return 0;
}

void print_img_file_header(PIMAGE_NT_HEADERS in_img_nt_headers)
{
        wprintf(L"IMAGE_NT_HEADERS (FileHeader)\n");
        wprintf(L"====================================================================\n");

        wprintf(L"  Characteristics       : %x\n", in_img_nt_headers->FileHeader.Characteristics);
        wprintf(L"  Machine               : %x\n", in_img_nt_headers->FileHeader.Machine);
        wprintf(L"  NumberOfSection       : %x\n", in_img_nt_headers->FileHeader.NumberOfSections);
        wprintf(L"  NumberOfSymbols       : %x\n", in_img_nt_headers->FileHeader.NumberOfSymbols);
        wprintf(L"  PointerToSymbolTable  : %x\n", in_img_nt_headers->FileHeader.PointerToSymbolTable);
        wprintf(L"  SizeOfOptionalHeader  : %x\n", in_img_nt_headers->FileHeader.SizeOfOptionalHeader);
        wprintf(L"  TimeDataStamp         : %x\n", in_img_nt_headers->FileHeader.TimeDateStamp);
        wprintf(L"\n====================================================================\n\n\n\n\n");
}

void print_img_optional_headers(PIMAGE_OPTIONAL_HEADER in_optional_header)
{
        LPCWSTR data_directory[16] =
        {
                L"EXPORT        ", L"IMPORT        ", L"RESOURCE      ", L"EXCEPTION     ", L"SECURITY      ", L"BASERELOC     ",
                L"DEBUG         ", L"ARCHITECTURE  ", L"GLOBALPTR     ", L"TLS           ", L"LOAD_CONFIG   ",
                L"BOUND_IMPORT  ", L"IAT           ", L"DELAY_IMPORT  ", L"COM_DESCRIPTOR"
        };
        UINT size_data_directory = sizeof(data_directory) / sizeof(data_directory[0]);

        wprintf(L"");

        wprintf(L"IMAGE_OPTIONAL_HEADER\n");
        wprintf(L"====================================================================\n");

        wprintf(L"  AddressOfEntryPoint              : %x\n", in_optional_header->AddressOfEntryPoint);
        wprintf(L"  BaseOfCode                       : %x\n", in_optional_header->BaseOfCode);
        wprintf(L"  CheckSum                         : %x\n", in_optional_header->CheckSum);
        wprintf(L"  DllCharacterstics                : %x\n", in_optional_header->DllCharacteristics);
        wprintf(L"  FileAligment                     : %x\n", in_optional_header->FileAlignment);
        wprintf(L"  FileAlignment                    : %x\n", in_optional_header->FileAlignment);
        wprintf(L"  ImageBase                        : %x\n", (LONG)in_optional_header->ImageBase);
        wprintf(L"  LoaderFlags                      : %x\n", in_optional_header->LoaderFlags);
        wprintf(L"  LoaderFlags                      : %x\n", in_optional_header->LoaderFlags);
        wprintf(L"  Magic                            : %x\n", in_optional_header->Magic);
        wprintf(L"  MajorImageVersion                : %x\n", in_optional_header->MajorImageVersion);
        wprintf(L"  MajorLinkerVersion               : %x\n", in_optional_header->MajorLinkerVersion);
        wprintf(L"  MajorOpratingSystemVersion       : %x\n", in_optional_header->MajorOperatingSystemVersion);
        wprintf(L"  MajorSubsystemVersion            : %x\n", in_optional_header->MajorSubsystemVersion);
        wprintf(L"  NumberOfRvaAndSizes              : %x\n", in_optional_header->NumberOfRvaAndSizes);
        wprintf(L"  SectionAlignment                 : %x\n", in_optional_header->SectionAlignment);
        wprintf(L"  SizeOfCode                       : %x\n", in_optional_header->SizeOfCode);
        wprintf(L"  SizeOfHeaders                    : %x\n", in_optional_header->SizeOfHeaders);
        wprintf(L"  SizeOfHeapCommit                 : %x\n", (LONG)in_optional_header->SizeOfHeapCommit);
        wprintf(L"  SizeOfHeapReserve                : %x\n", (LONG)in_optional_header->SizeOfHeapReserve);
        wprintf(L"  SizeOfImage                      : %x\n", in_optional_header->SizeOfImage);
        wprintf(L"  SizeOfInitializedData            : %x\n", in_optional_header->SizeOfInitializedData);
        wprintf(L"  SizeOfStackCommit                : %x\n", (LONG)in_optional_header->SizeOfStackCommit);
        wprintf(L"  SizeOfHeapReverse                : %x\n", (LONG)in_optional_header->SizeOfHeapReserve);
        wprintf(L"  SizeOfUnitializedData            : %x\n", in_optional_header->SizeOfUninitializedData);
        wprintf(L"  Subsystem                        : %x\n", in_optional_header->Subsystem);
        wprintf(L"  Win32VersionValue                : %x\n\n", in_optional_header->Win32VersionValue);

        wprintf(L"==== Data Directory ===\r\n");
        wprintf(L"Name                    RAV                  Size\r\n");
        wprintf(L"-------------       -----------        ------------\r\n");
        for (UINT i = 0; i < in_optional_header->NumberOfRvaAndSizes - 1 && i < size_data_directory * 3; ++i)
        {
                wprintf(L"  %s       0x%-8X          0x%-8X\r\n", data_directory[i], in_optional_header->DataDirectory[i].VirtualAddress, in_optional_header->DataDirectory[i].Size);
        }
        wprintf(L"\n====================================================================\n\n\n\n\n");
}

void print_img_section_table(PIMAGE_OPTIONAL_HEADER in_img_optional_header, const WORD in_number_of_section)
{
        wprintf(L"==============   Section Table   ==============\n\n");

        PIMAGE_SECTION_HEADER img_section_header = (PIMAGE_SECTION_HEADER)((PBYTE)in_img_optional_header + sizeof(IMAGE_OPTIONAL_HEADER));

        for (WORD i = 0; i < in_number_of_section; ++i)
        {
                wprintf(L"  %02hd %hs\r\n", 1 + i, img_section_header[i].Name);

                wprintf(L"      Virtual Size         : %08hx   Virtual Address      : %08hx  Physical Address     : %08hx\r\n", img_section_header[i].Misc.VirtualSize, img_section_header->VirtualAddress, img_section_header->Misc.PhysicalAddress);
                wprintf(L"      SizeOfRawData        : %08hx   PointerToRawData     : %08hx\r\n", img_section_header[i].SizeOfRawData, img_section_header[i].PointerToRawData);
                wprintf(L"      PointerToRawData     : %08hx   PointerToRelocations : %08hx  PointerToRelocations : %08hx\r\n", img_section_header[i].PointerToRawData, img_section_header[i].PointerToRelocations, img_section_header[i].PointerToRelocations);
                wprintf(L"      NumberOfRelocations  : %08hx   NumberOfLinenumbers  : %08hx\r\n", img_section_header[i].NumberOfRelocations, img_section_header[i].NumberOfLinenumbers);
                wprintf(L"      Characteristics      : %08hx\r\n\n", img_section_header[i].Characteristics);
        }
}