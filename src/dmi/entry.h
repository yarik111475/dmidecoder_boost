#ifndef ENTRY_H
#define ENTRY_H

#include <string>

struct entry
{
    //dmi anchor (must be _SM_, _SM3_ or _DMI_)
    std::string ep_anchor_ {};

    //entry point length
    unsigned char ep_length_ {0};

    //smbios major version
    unsigned char ep_major_version_ {};

    //smbios minor version
    unsigned char ep_minor_version_ {};

    //structures size
    int ep_max_structure_size_ {};

    //revision
    unsigned char ep_revision_ {};

    //length of dmi table
    int ep_table_length_ {};

    //structures count in dmi table
    int ep_number_of_structures_ {};
};

#endif // ENTRY_H
