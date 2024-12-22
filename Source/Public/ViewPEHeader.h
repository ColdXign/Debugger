#pragma once

//struct PIMAGE_DOS_HEADER;
//struct PIMAGE_NT_HEADERS;
//struct PIMAGE_DATA_DIRECTORY;
//struct PIMAGE_IMPORT_DESCRIPTOR;

struct pe_struct
{
        HANDLE m_file, m_file_mapping;

        PIMAGE_DOS_HEADER m_img_dos_header;
        PIMAGE_NT_HEADERS m_img_nt_headers;
        PIMAGE_DATA_DIRECTORY m_img_data_directory;
        PIMAGE_IMPORT_DESCRIPTOR m_img_import_desc;
};

bool __stdcall load_pe_headers();
bool __stdcall unload_file_pe(HANDLE in_hfile, HANDLE in_hfile_mapping, struct pe_struct* in_pe_headers);

struct pe_struct* load_file(struct pe_struct** in_pe_headers);

void __stdcall print_image_dos_headers(PIMAGE_DOS_HEADER in_img_dos_header);
DWORD __stdcall  check_signature(PIMAGE_NT_HEADERS in_img_nt_headers);
void __stdcall print_img_file_header(PIMAGE_NT_HEADERS in_img_nt_headerss);
void __stdcall print_img_optional_headers(PIMAGE_OPTIONAL_HEADER in_img_optional_header);
void __stdcall print_img_section_table(PIMAGE_OPTIONAL_HEADER in_img_optional_header, const WORD in_number_of_section);