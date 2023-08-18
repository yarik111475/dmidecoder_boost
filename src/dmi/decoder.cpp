#include "decoder.h"

#include <cmath>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <numeric>

#include <boost/json.hpp>
#include <boost/format.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

//part for windows os
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sysinfoapi.h>

struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[];
};
#endif

bool decoder::checksum(const std::vector<char> &data)
{
    int init {0};
    int sum {std::accumulate(data.begin(),data.end(),init,[](int init, char item){
            return init+=static_cast<unsigned char>(item);
        })};
    return (sum!=0);
}

bool decoder::decode_entry()
{
    //create input filestream
    std::ifstream ifs(entry_path_,std::ios::binary);
    std::istreambuf_iterator<char> begin {ifs};
    std::istreambuf_iterator<char> end {};

    //read entry_point content
    std::vector<char> content_;
    content_.assign(begin,end);

    //check file content checksum
    if(!checksum(content_)){
        error_str_="Checksum error";
        return false;
    }

    //smbios entry point
    entry entry;

    //check entry anchor
    entry.ep_anchor_=std::string{content_.begin(),content_.begin()+4};
    auto found {std::find(anchors_.begin(),anchors_.end(),entry.ep_anchor_)};
    if(found==anchors_.end()){
        entry.ep_anchor_=std::string{content_.begin(),content_.begin()+5};
        found=std::find(anchors_.begin(),anchors_.end(),entry.ep_anchor_);
        if(found==anchors_.end()){
            return false;
        }
    }

    //check entry point length
    entry.ep_length_=(entry.ep_anchor_=="_SM_") ? static_cast<unsigned char>(content_.at(0x05)) :
                     (entry.ep_anchor_=="_SM3_") ? static_cast<unsigned char>(content_.at(0x06)) : 0;

    if(!entry.ep_length_ || (entry.ep_length_ > content_.size())){
        error_str_="Entry point length error";
        return false;
    }

    if(entry.ep_anchor_=="_SM_"){
        //get smbios major/minor versions
        entry.ep_major_version_=static_cast<unsigned char>(content_.at(0x06));
        entry.ep_minor_version_=static_cast<unsigned char>(content_.at(0x07));

        //get max structures size
        entry.ep_max_structure_size_=static_cast<unsigned char>(content_.at(0x09)) * 0x100 +
                                     static_cast<unsigned char>(content_.at(0x08));

        //get revision
        entry.ep_revision_=static_cast<unsigned char>(content_.at(0x0A));

        //get dmi table length
        entry.ep_table_length_=static_cast<unsigned char>(content_.at(0x17)) * 0x100 +
                               static_cast<unsigned char>(content_.at(0x16));

        //get number of smbios structures
        entry.ep_number_of_structures_=static_cast<unsigned char>(content_.at(0x1D)) * 0x100 +
                                       static_cast<unsigned char>(content_.at(0x1C));
    }
    else{
        //get smbios major/minor versions
        entry.ep_major_version_=static_cast<unsigned char>(content_.at(0x07));
        entry.ep_minor_version_=static_cast<unsigned char>(content_.at(0x08));

        //get revision
        entry.ep_revision_=static_cast<unsigned char>(content_.at(0x0A));
    }

    return true;
}

std::vector<structure> decoder::decode_table()
{
    std::vector<structure> dmi_list;
    std::vector<char> content_ {};

//part for linux
#if defined (__linux__) || defined(__linux) || defined(__gnu_linux__)
    //create input filestream
    std::ifstream ifs(table_path_,std::ios::binary);
    std::istreambuf_iterator<char> begin {ifs};
    std::istreambuf_iterator<char> end {};

    //read dmi tables content
    content_.assign(begin,end);
#endif

//part for windows
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    DWORD smbios_data_size {0};
    RawSMBIOSData* smbios_data {NULL}; //Defined in this link
    DWORD bytes_written {0};

    //Query size of SMBIOS data.
    smbios_data_size=GetSystemFirmwareTable('RSMB', 0, NULL, 0);

    //Allocate memory for SMBIOS data
    smbios_data=(RawSMBIOSData*) HeapAlloc(GetProcessHeap(), 0, smbios_data_size);
    if (!smbios_data) {
        error_str_="Fail to allocate memory for SMBIOS structure";
        return dmi_list;
    }

    //Retrieve the SMBIOS table
    bytes_written=GetSystemFirmwareTable('RSMB', 0, smbios_data, smbios_data_size);
    if(!bytes_written){
        error_str_="Fail to read SMBIOS information";
        return dmi_list;
    }
    std::copy(&(smbios_data->SMBIOSTableData[0]),&(smbios_data->SMBIOSTableData[smbios_data->Length]),std::back_inserter(content_));
    smbios_data=NULL;
#endif

    //check file content checksum
    if(!checksum(content_)){
        error_str_="SMBIOS checksum error";
        return dmi_list;
    }

    //structure header size
    const int& header_size (4);

    //parse structures
    for(auto iterator=content_.begin();iterator<content_.end();++iterator){
        //check if header block can be readed
        if((iterator + header_size)>=content_.end()){
            return dmi_list;
        }

        //get header buffer, header type, data block length and handle
        std::vector<char> header_buffer;
        header_buffer.assign(iterator,iterator+header_size);
        const int& type (static_cast<unsigned char>(header_buffer.at(0)));
        const int& length (static_cast<unsigned char>(header_buffer.at(1)));
        const int& handle {static_cast<unsigned char>(header_buffer.at(3)) * 0x100 +
                           static_cast<unsigned char>(header_buffer.at(2))};

        //check if data block can be readed;
        if((iterator+length) >=content_.end()){
            return dmi_list;
        }

        //read data block
        std::vector<char> data;
        data.assign(iterator,iterator+length);
        iterator+=length;

        //read strings block
        std::vector<std::string> strings;
        std::string string_item {};
        while(iterator!=content_.end()){
            if((iterator+2)==content_.end()){
                strings.push_back(string_item);
                string_item.clear();
                break;
            }
            if(*iterator=='\0' && *(iterator+1)=='\0'){
                strings.push_back(string_item);
                string_item.clear();
                break;
            }
            if(*iterator=='\0' && *(iterator+1)!='\0'){
                strings.push_back(string_item);
                string_item.clear();
                ++iterator;
                continue;
            }
            string_item.push_back(*iterator);
            ++iterator;
        }
        iterator+=1;

        //create result dmi structure
        structure dmi(
            type,length,handle,data,strings
        );
        dmi_list.push_back(dmi);
    }
    return dmi_list;
}

boost::json::object decoder::decode_structure(const structure &dmi, int type)
{
    boost::json::object json;
    switch(type){
    case 0:
        json=bios_information(dmi);
        break;
    case 1:
        json=system_information(dmi);
        break;
    case 2:
        json=baseboard_information(dmi);
        break;
    case 3:
        json=chassis_information(dmi);
        break;
    case 4:
        json=processor_information(dmi);
        break;
    case 5:
        json=memory_controller_information(dmi);
        break;
    case 6:
        json=memory_module_information(dmi);
        break;
    case 7:
        json=cache_information(dmi);
        break;
    case 8:
        json=port_connector_information(dmi);
        break;
    case 9:
        json=system_slot_information(dmi);
        break;
    case 10:
        json=onboard_device_information(dmi);
        break;
    case 11:
        json=oem_strings(dmi);
        break;
    case 12:
        json=system_configuration_options(dmi);
        break;
    case 13:
        json=bios_language_information(dmi);
        break;
    case 16:
        json=physical_memory_array(dmi);
        break;
    case 17:
        json=memory_device(dmi);
        break;
    case 18:
        json=memory_error_information(dmi);
        break;
    case 21:
        json=builtin_pointing_device(dmi);
        break;
    case 22:
        json=portable_battery(dmi);
        break;
    case 26:
        json=voltage_probe(dmi);
        break;
    case 27:
        json=cooling_device(dmi);
        break;
    case 28:
        json=temperature_probe(dmi);
        break;
    case 29:
        json=electrical_current_probe(dmi);
        break;
    case 34:
        json=management_device_information(dmi);
        break;
    case 37:
        break;
    case 38:
        break;
    case 40:
        break;
    case 41:
        json=onboard_device_extended_information(dmi);
        break;
    case 42:
        break;
    case 44:
        json=processor_additional_information(dmi);
        break;
    }
    if(!json.empty()){
        //out_object.insert("hash", dmi.hash_);
        json.emplace("type", dmi.type_);
        json.emplace("handle", dmi.handle_);
    }

    return json;
}

std::vector<std::pair<std::string, std::string> > decoder::decode_information()
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    const bool& ep_success {true};
#endif
#if defined (__linux__) || defined(__linux) || defined(__gnu_linux__)
    const bool& ep_success{decode_entry()};
#endif

    if(ep_success){
        structure_list_ =decode_table();
        if(!structure_list_.empty()){
            //decode simple structures
            for(const structure& dmi: structure_list_){
                boost::json::object dmi_object {decode_structure(dmi, dmi.type_)};
                if(!dmi_object.empty() && dmi_object.contains("object_type")){
                    dmi_list_.push_back(std::make_pair(dmi_object.at("object_type").as_string().c_str(),
                                                       boost::json::serialize(dmi_object)));
                }
            }

            //decode structure associations
            const int& associations_type {14};
            std::for_each(structure_list_.begin(),structure_list_.end(),[&associations_type,this](const structure& dmi){
                if(dmi.type_==associations_type){
                    group_associations(dmi);
                }
            });
        }
    }
    return dmi_list_;
}

//Type 0
boost::json::object decoder::bios_information(const structure &dmi)
{
    //get bios characteristics
    const auto& characteristics_get{[](const unsigned int key){
            const std::map<unsigned int,std::string>& chars_map{
                {0x1,"Reserved"},
                {0x2,"Reserved"},
                {0x4,"Unknown"},
                {0x8,"BIOS Characteristics are not supported"},
                {0x10,"ISA is supported"},
                {0x20,"MCA is supported"},
                {0x40,"EISA is supported"},
                {0x80,"PCI is supported"},
                {0x100,"PC card (PCMCIA) is supported"},
                {0x200,"Plug and Play is supported"},
                {0x400,"APM is supported"},
                {0x800,"BIOS is upgradeable (Flash)"},
                {0x1000,"BIOS shadowing is allowed"},
                {0x2000,"VL-VESA is supported"},
                {0x4000,"ESCD support is available"},
                {0x8000,"Boot from CD is supported"},
                {0x10000,"Selectable boot is supported"},
                {0x20000,"BIOS ROM is socketed (e.g. PLCC or SOP socket)"},
                {0x40000,"Boot from PC card (PCMCIA) is supported"},
                {0x80000,"EDD specification is supported"},
                {0x100000,"Int 13h-Japanese floppy for NEC 9800 1.2 MB (3.5”, 1K bytes/sector, 360 RPM) is supported"},
                {0x200000,"Int 13h-Japanese floppy for Toshiba 1.2 MB (3.5”, 360 RPM) is supported"},
                {0x400000,"Int 13h-5.25” / 360 KB floppy services are supported"},
                {0x800000,"Int 13h-5.25” /1.2 MB floppy services are supported"},
                {0x1000000,"Int 13h-3.5” / 720 KB floppy services are supported"},
                {0x2000000,"Int 13h-3.5” / 2.88 MB floppy services are supported"},
                {0x4000000,"Int 5h print screen Service is supported"},
                {0x8000000,"Int 9h 8042 keyboard services are supported"},
                {0x10000000,"Int 14h serial services are supported"},
                {0x20000000,"Int 17h printer services are supported"},
                {0x40000000,"Int 10h CGA/Mono Video Services are supported"},
                {0x80000000,"NEC PC-98"}
            };
            std::vector<std::string> characteristics {};
            for(const auto& pair: chars_map){
                if((key & pair.first)){
                    characteristics.push_back(pair.second);
                }
            }
            return characteristics;
        }
    };

    //get ext characteristics
    const auto& ext_characteristics_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& ext_map{
                {0x01,"ACPI is supported"},
                {0x02,"USB Legacy is supported"},
                {0x04,"AGP is supported"},
                {0x08,"I2O boot is supported"},
                {0x10,"LS-120 SuperDisk boot is supported"},
                {0x20,"ATAPI ZIP drive boot is supported"},
                {0x40,"1394 boot is supported"},
                {0x80,"Smart battery is supported"}
            };
            std::vector<std::string> ext_characteristics {};
            for(const auto& pair: ext_map){
                if((key & pair.first)){
                    ext_characteristics.push_back(pair.second);
                }
            }
            return ext_characteristics;
        }
    };

    const int& vendor_locator {dmi.data_.size() > 0x04 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x04))-1) : -1};

    std::string vendor {};
    if((dmi.strings_.size() > vendor_locator) && (vendor_locator >= 0)){
        vendor=boost::trim_copy(dmi.strings_.at(vendor_locator));
    }

    const int& version_locator {dmi.data_.size() > 0x05 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x05))-1) : -1};

    std::string version {};
    if((dmi.strings_.size() > version_locator) && (version_locator >= 0)){
        version=boost::trim_copy(dmi.strings_.at(version_locator));
    }

    const int& release_locator {dmi.data_.size() > 0x08 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x08))-1) : -1};

    std::string release_date {};
    if((dmi.strings_.size() > release_locator) && (release_locator >= 0)){
        release_date=boost::trim_copy(dmi.strings_.at(release_locator));
    }
    const int& rom_size {dmi.data_.size() > 0x09 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x09))+1) : 0};

    //characteristics key (low 4 bytes)
    const unsigned int& chars_key (dmi.data_.size()>0x0E ?
                    (((static_cast<unsigned char>(dmi.data_.at(0x0D))) * 0x1000000) +
                    ((static_cast<unsigned char>(dmi.data_.at(0x0C))) * 0x10000) +
                    ((static_cast<unsigned char>(dmi.data_.at(0x0B))) * 0x100) +
                      static_cast<unsigned char>(dmi.data_.at(0x0A))) : -1);

    //characteristics list
    const std::vector<std::string>& charcteristics {characteristics_get(chars_key)};

    //ext characteristics ke (first byte)
    const unsigned int& ext_chars_key_1 (dmi.data_.size()>0x12 ?
                    static_cast<unsigned char>(dmi.data_.at(0x12)) : -1);
    //ext characteristics
    const std::vector<std::string>& ext_characteristics {ext_characteristics_get(ext_chars_key_1)};

    std::string bios_release {};
    if(dmi.data_.size() > 0x15){
        const std::string& major_release {std::to_string(static_cast<unsigned char>(dmi.data_.at(0x14)))};
        const std::string& minor_release {std::to_string(static_cast<unsigned char>(dmi.data_.at(0x15)))};
        bios_release=(boost::format("%s.%s")
                      % major_release
                      % minor_release).str();
    }


    const boost::json::object& out_object {
        {"object_type", "bios_information"},
        {"vendor", vendor},
        {"version", version},
        {"release_date", release_date},
        {"rom_size", rom_size * (1024 * 64)},
        {"characteristics", boost::join(charcteristics,", ")},
        {"ext_characteristics", boost::join(ext_characteristics,", ")},
        {"bios_release", bios_release}
    };
    return out_object;
}

//Type 1
boost::json::object decoder::system_information(const structure &dmi)
{
    const auto& wakeup_get{[](unsigned char key){
            std::map<unsigned char,std::string> wakeup_map{
                {0x00,"Reserved"},
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"APM Timer"},
                {0x04,"Modem Ring"},
                {0x05,"LAN Remote"},
                {0x06,"Power Switch"},
                {0x07,"PCI PME#"},
                {0x08,"AC Power Restored"}
            };
            const auto& found {wakeup_map.find(key)};
            if(found!=wakeup_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& manufacturer_locator ((dmi.data_.size() > 0x04) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x04)-1)) : -1);

    std::string manufacturer {};
    if((manufacturer_locator >= 0) && (dmi.strings_.size() > manufacturer_locator)){
        manufacturer=boost::trim_copy(dmi.strings_.at(manufacturer_locator));
    }

    const int& product_locator ((dmi.data_.size() > 0x05) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x05)-1)) : -1);

    std::string product_name {};
    if((product_locator >= 0) && (dmi.strings_.size() > product_locator)){
        product_name=boost::trim_copy(dmi.strings_.at(product_locator));
    }

    const int& version_locator {(dmi.data_.size() > 0x06) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x06)-1)) : -1};

    std::string version {};
    if((version_locator>=0) && (dmi.strings_.size()>version_locator)){
        version=boost::trim_copy(dmi.strings_.at(version_locator));
    }

    const int& serial_locator {(dmi.data_.size() > 0x07) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x07)-1)) : -1};

    std::string serial_number {};
    if((serial_locator>=0) && (dmi.strings_.size()>serial_locator)){
        serial_number=boost::trim_copy(dmi.strings_.at(serial_locator));
    }

    std::string uuid {};
    if(dmi.data_.size() > 0x18){
        std::vector<char> uuid_data;
        uuid_data.assign(dmi.data_.begin()+0x08,dmi.data_.begin()+0x18);
        boost::uuids::uuid u;
        memcpy(&u,uuid_data.data(),uuid_data.size());
        uuid=boost::lexical_cast<std::string>(u);
    }

    const std::string& wakeup_type {dmi.data_.size() > 0x18 ?
                   wakeup_get(static_cast<unsigned char>(dmi.data_.at(0x18))) :
                    std::string {}};

    const int& sku_locator {(dmi.data_.size() > 0x19) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x19)-1)) : -1};

    std::string sku_number {};
    if((sku_locator>=0) && (dmi.strings_.size()>sku_locator)){
        sku_number=boost::trim_copy(dmi.strings_.at(sku_locator));
    }

    const int& family_locator {(dmi.data_.size() > 0x1A) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x1A)-1)) : -1};

    std::string family {};
    if((family_locator>=0) && (dmi.strings_.size()>family_locator)){
        family=boost::trim_copy(dmi.strings_.at(family_locator));
    }

    const boost::json::object& out_object {
        {"object_type", "system_information"},
        {"manufacturer", manufacturer},
        {"product_name", product_name},
        {"version", version},
        {"serial_number", serial_number},
        {"uuid", uuid},
        {"wakeup_type", wakeup_type},
        {"sku_number", sku_number},
        {"family", family}
    };
    return out_object;
}

//Type 2
boost::json::object decoder::baseboard_information(const structure &dmi)
{
    //get baseboard feature
    const auto& feature_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& feature_map{
                {0x01, "Hosting board"},
                {0x02,"Daughter required"},
                {0x04,"Removable"},
                {0x08,"Replaceable"},
                {0x10,"Hot swappable"}
            };

            std::vector<std::string> features {};
            for(const auto& pair: feature_map){
                if((pair.first & key)!=0){
                    features.push_back(pair.second);
                }
            }
            return features;
        }
    };

    //get board type
    const auto& board_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& board_map{
                {0x01,"Unknown"},
                {0x02,"Other"},
                {0x03,"Server Blade"},
                {0x04,"Connectivity Switch"},
                {0x05,"System Management Module"},
                {0x06,"Processor Module"},
                {0x07,"I/O Module"},
                {0x08,"Memory Module"},
                {0x09,"Daughter board"},
                {0x0A,"Motherboard"},
                {0x0B,"Processor/Memory Module"},
                {0x0C,"Processor/IO Module"},
                {0x0D,"Interconnect board"}
            };
            const auto& found {board_map.find(key)};
            if(found!=board_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& manufacturer_locator {(dmi.data_.size() > 0x04) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x04)-1)) : -1};

    std::string manufacturer {};
    if((manufacturer_locator>=0) && (dmi.strings_.size()>manufacturer_locator)){
        manufacturer=boost::trim_copy(dmi.strings_.at(manufacturer_locator));
    }

    const int& product_locator {(dmi.data_.size() > 0x05) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x05)-1)) : -1};

    std::string product {};
    if((product_locator>=0) && (dmi.strings_.size()>product_locator)){
        product=boost::trim_copy(dmi.strings_.at(product_locator));
    }

    const int& version_locator {(dmi.data_.size() > 0x06) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x06)-1)) : -1};

    std::string version {};
    if((version_locator>=0) && (dmi.strings_.size()>version_locator)){
        version=boost::trim_copy(dmi.strings_.at(version_locator));
    }

    const int& serial_locator {(dmi.data_.size() > 0x07) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x07)-1)) : -1};

    std::string serial_number {};
    if((serial_locator>=0) && (dmi.strings_.size()>serial_locator)){
        serial_number=boost::trim_copy(dmi.strings_.at(serial_locator));
    }

    const int& asset_locator {(dmi.data_.size() > 0x08) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x08)-1)) : -1};

    std::string asset_tag {};
    if((asset_locator>=0) && (dmi.strings_.size()>asset_locator)){
        asset_tag=boost::trim_copy(dmi.strings_.at(asset_locator));
    }

    const std::vector<std::string>& feature {dmi.data_.size() > 0x09 ?
                    feature_get(static_cast<unsigned char>(dmi.data_.at(0x09))) :
                    std::vector<std::string>{}};

    const int& chassis_locator {(dmi.data_.size() > 0x0A) ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0A)-1)) : -1};

    std::string chassis_location {};
    if((chassis_locator>=0) && (dmi.strings_.size()>chassis_locator)){
        chassis_location=boost::trim_copy(dmi.strings_.at(chassis_locator));
    }

    const std::string& board_type {dmi.data_.size() > 0x0D ?
                    board_get(static_cast<unsigned char>(dmi.data_.at(0x0D))) :
                    std::string {}};

    const boost::json::object& out_object {
        {"object_type", "baseboard_information"},
        {"manufacturer", manufacturer},
        {"product", product},
        {"version", version},
        {"serial_number", serial_number},
        {"feature", boost::join(feature,", ")},
        {"asset_tag", asset_tag},
        {"chassis_location", chassis_location},
        {"board_type", board_type}
    };
    return out_object;
}

//Type 3
boost::json::object decoder::chassis_information(const structure &dmi)
{
    //get chassis type
    const auto& chassis_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string> type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Desktop"},
                {0x04,"Low Profile Desktop"},
                {0x05,"Pizza Box"},
                {0x06,"Mini Tower"},
                {0x07,"Tower"},
                {0x08,"Portable"},
                {0x09,"Laptop"},
                {0x0A,"Notebook"},
                {0x0B,"Hand Held"},
                {0x0C,"Docking Station"},
                {0x0D,"All in One"},
                {0x0E,"Sub Notebook"},
                {0x0F,"Space-saving"},
                {0x10,"Lunch Box"},
                {0x11,"Main Server Chassis"},
                {0x12,"Expansion Chassis"},
                {0x13," SubChassis"},
                {0x14,"Bus Expansion Chassis"},
                {0x15,"Peripheral Chassis"},
                {0x16,"RAID Chassis"},
                {0x17,"Rack Mount Chassis"},
                {0x18,"Sealed-case PC"},
                {0x19,"Multi-system chassis"},
                {0x1A,"Compact PCI"},
                {0x1B,"Advanced TCA"},
                {0x1C,"Blade"},
                {0x1D,"Blade Enclosure"},
                {0x1E,"Tablet"},
                {0x1F,"Convertible"},
                {0x20,"Detachable"},
                {0x21,"IoT Gateway"},
                {0x22,"Embedded PC"},
                {0x23,"Mini PC"},
                {0x24,"Stick PC"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get chassis state
    const auto& chassis_state_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& state_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Safe"},
                {0x04,"Warning"},
                {0x05,"Critical"},
                {0x06,"Non-recoverable"}
            };
            const auto& found {state_map.find(key)};
            if(found!=state_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get security status
    const auto& security_status_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& status_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"None"},
                {0x04,"External interface locked out"},
                {0x05,"External interface enabled"}
            };
            const auto& found {status_map.find(key)};
            if(found!=status_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& manufacturer_locator (dmi.data_.size()>0x04 ?
                                         static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);
    const std::string& manufacturer (manufacturer_locator>=0 && dmi.strings_.size()>manufacturer_locator ?
                                     boost::trim_copy(dmi.strings_.at(manufacturer_locator)) :
                                         std::string {});

    const std::string& chassis_type(dmi.data_.size()>0x05 ?
                            chassis_type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                std::string {});

    const int& version_locator (dmi.data_.size()>0x06 ?
                                         static_cast<unsigned char>(dmi.data_.at(0x06))-1 : -1);
    const std::string& version (version_locator>=0 && dmi.strings_.size()>version_locator ?
                                     boost::trim_copy(dmi.strings_.at(version_locator)) :
                                    std::string {});

    const int& serial_locator (dmi.data_.size()>0x07 ?
                                         static_cast<unsigned char>(dmi.data_.at(0x07))-1 : -1);
    const std::string& serial_number (serial_locator>=0 && dmi.strings_.size()>serial_locator ?
                                     boost::trim_copy(dmi.strings_.at(serial_locator)) :
                                          std::string {});

    const int& asset_locator (dmi.data_.size()>0x08 ?
                                         static_cast<unsigned char>(dmi.data_.at(0x08))-1 : -1);
    const std::string& asset_tag (asset_locator>=0 && dmi.strings_.size()>asset_locator ?
                                     boost::trim_copy(dmi.strings_.at(asset_locator)) :
                                      std::string {});

    const std::string& bootup_state (dmi.data_.size()>0x09 ?
                                     chassis_state_get(static_cast<unsigned char>(dmi.data_.at(0x09))) :
                                         std::string {});

    const std::string& power_supply_state (dmi.data_.size()>0x0A ?
                                     chassis_state_get(static_cast<unsigned char>(dmi.data_.at(0x0A))) :
                                               std::string {});

    const std::string& thermal_state (dmi.data_.size()>0x0B ?
                                     chassis_state_get(static_cast<unsigned char>(dmi.data_.at(0x0B))) :
                                          std::string {});

    const std::string& security_status (dmi.data_.size()>0x0C ?
                                        security_status_get(static_cast<unsigned char>(dmi.data_.at(0x0C))) :
                                            std::string {});

    const int& height (dmi.data_.size()>0x11 ?
                          static_cast<unsigned char>(dmi.data_.at(0x11)) : 0);

    const int sku_locator (dmi.data_.size()>0x15 ?
                               static_cast<unsigned char>(dmi.data_.at(0x15))-1 : -1);

    const std::string& sku_number (sku_locator>=0 && dmi.strings_.size()>sku_locator ?
                                   boost::trim_copy(dmi.strings_.at(sku_locator)) :
                                   std::string {});

    const boost::json::object& out_object{
        {"object_type", "chassis_information"},
        {"manufacturer", manufacturer},
        {"chassis_type", chassis_type},
        {"version", version},
        {"serial_number", serial_number},
        {"asset_tag", asset_tag},
        {"bootup_state", bootup_state},
        {"power_supply_state", power_supply_state},
        {"thermal_state", thermal_state},
        {"security_status", security_status},
        {"sku_number", sku_number},
        {"height", height}
    };
    return out_object;
}

//Type 4
boost::json::object decoder::processor_information(const structure &dmi)
{
    //get processor type
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Central Processor"},
                {0x04,"Math Processor"},
                {0x05,"DSP Processor"},
                {0x06,"Video Processor"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get cpu voltage
    const auto& voltage_get{[](unsigned char key){
            std::vector<std::string> voltage_list {};
            const std::map<unsigned char,std::string>& voltage_map{
                {0b001,"5v"},
                {0b010,"3.3v"},
                {0b100,"2.9v"}
            };
            if(!(key & 0x80)){
                for(const auto& pair: voltage_map){
                    if((pair.first & key)!=0){
                        voltage_list.push_back(pair.second);
                    }
                }
            }
            else{
                const int& value (key & ~(0x80));
                voltage_list.push_back((boost::format("%1.1fv")
                                        % (key/100.0)).str());
            }
            return voltage_list;
        }
    };

    //get processor upgrade
    const auto& upgrade_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& upgrade_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Daughter Board"},
                {0x04,"ZIF Socket"},
                {0x05,"Replaceable Piggy Back"},
                {0x06,"None"},
                {0x07,"LIF Socket"},
                {0x08,"Slot 1"},
                {0x09,"Slot 2"},
                {0x0A,"370-pin socket"},
                {0x0B,"Slot A"},
                {0x0C,"Slot M"},
                {0x0D,"Socket 423"},
                {0x0E,"Socket A (Socket 462)"},
                {0x0F,"Socket 478"},
                {0x010,"Socket 754"},
                {0x11,"Socket 940"},
                {0x12,"Socket 939"},
                {0x13,"Socket mPGA604"},
                {0x14,"Socket LGA771"},
                {0x15,"Socket LGA775"},
                {0x16,"Socket S1"},
                {0x17,"Socket AM2"},
                {0x18,"Socket F (1207)"},
                {0x19,"Socket LGA1366"},
                {0x1A,"Socket G34"},
                {0x1B,"Socket AM3"},
                {0x1C,"Socket C32"},
                {0x1D,"Socket LGA1156"},
                {0x1E,"Socket LGA1556"},
                {0x1F,"Socket PGA988A"},
                {0x20,"Socket BGA1288"},
                {0x21,"Socket rPGA988B"},
                {0x22,"Socket BGA1023"},
                {0x23,"Socket BGA1224"},
                {0x24,"Socket LGA1155"},
                {0x25,"Socket LGA1356"},
                {0x26,"Socket LGA2011"},
                {0x27,"Socket FS1"},
                {0x28,"Socket FS2"},
                {0x29,"Socket FM1"},
                {0x2A,"Socket FM2"},
                {0x2B,"Socket LGA2011-3"},
                {0x2C,"Socket LGA1356-3"},
                {0x2D,"Socket LGA1150"},
                {0x2E,"Socket BGA1168"},
                {0x2F,"Socket BGA1234"},
                {0x30,"Socket BGA1234"},
                {0x31,"Socket AM4"},
                {0x32,"Socket LGA1151"},
                {0x33,"Socket LGA1151"},
                {0x34,"Socket BGA1440"},
                {0x35,"Socket BGA1515"},
                {0x36,"Socket LGA3647-1"},
                {0x37,"Socket SP3"},
                {0x38,"Socket SP3r2"},
                {0x39,"Socket LGA2066"},
                {0x3A,"Socket BGA1392"},
                {0x3B,"Socket BGA1510"},
                {0x3C,"Socket BGA1528"},
                {0x3D,"Socket LGA4189"},
                {0x3E,"Socket LGA1200"},
                {0x3F,"Socket LGA4677"},
                {0x40,"Socket LGA1700"},
                {0x41,"Socket BGA1744"},
                {0x42,"Socket BGA1781"},
                {0x43,"Socket BGA1211"},
                {0x44,"Socket BGA2422"},
                {0x45,"Socket LGA1211"},
                {0x46,"Socket LGA2422"},
                {0x47,"Socket LGA5773"},
                {0x48,"Socket BGA5773"}
            };
            const auto& found {upgrade_map.find(key)};
            if(found!=upgrade_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get processor family
    const auto& family_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& family_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"8086"},
                {0x04,"80286"},
                {0x05,"Intel386™ processor"},
                {0x06,"ntel486™ processor"},
                {0x07,"8087"},
                {0x08,"80287"},
                {0x09,"80387"},
                {0x0A,"8487"},
                {0x0B,"Intel® Pentium® processor"},
                {0x0C,"Pentium® Pro processor"},
                {0x0D,"Pentium® II processor"},
                {0x0E,"Pentium® processor with MMX™ technology"},
                {0x0F,"Intel® Celeron® processor"},
                {0x10,"Pentium® II Xeon™ processor"},
                {0x11,"Pentium® III processor"},
                {0x12,"M1 Family"},
                {0x13,"M2 Family"},
                {0x14,"Intel® Celeron® M processor"},
                {0x15,"Intel® Pentium® 4 HT processor"},
                {0x16,"Not assignment"},
                {0x17,"Not assignment"},
                {0x18,"AMD Duron™ Processor Family "},
                {0x19,"K5 Family"},
                {0x1A,"K6 Family"},
                {0x1B,"K6-2"},
                {0x1C,"K6-3"},
                {0x1D,"AMD Athlon™ Processor Family "},
                {0x1E,"AMD29000 Family"},
                {0x1F,"K6-2+"},
                {0x20,"Power PC Family"},
                {0x21,"Power PC 601"},
                {0x22,"Power PC 603"},
                {0x23,"Power PC 603+"},
                {0x24,"Power PC 604"},
                {0x25,"Power PC 620"},
                {0x26,"Power PC x704"},
                {0x27,"Power PC 750"},
                {0x28,"Intel® Core™ Duo processor"},
                {0x29,"Intel® Core™ Duo mobile processor"},
                {0x2A,"Intel® Core™ Solo mobile processor"},
                {0x2B,"Intel® Atom™ processor"},
                {0x2C,"Intel® Core™ M processor"},
                {0x2D,"Intel(R) Core(TM) m3 processor"},
                {0x2E,"Intel(R) Core(TM) m5 processor"},
                {0x2F,"Intel(R) Core(TM) m7 processor"},
                {0x30,"Alpha Family "},
                {0x31,"Alpha 21064"},
                {0x32,"Alpha 21066"},
                {0x33,"Alpha 21164"},
                {0x34,"Alpha 21164PC"},
                {0x35,"Alpha 21164a"},
                {0x36,"Alpha 21264"},
                {0x37,"Alpha 21364"},
                {0x38,"AMD Turion™ II Ultra Dual-Core Mobile M Processor Family"},
                {0x39,"AMD Turion™ II Dual-Core Mobile M Processor Family"},
                {0x3A,"AMD Athlon™ II Dual-Core M Processor Family"},
                {0x3B,"AMD Opteron™ 6100 Series Processor"},
                {0x3C,"AMD Opteron™ 4100 Series Processor"},
                {0x3D,"AMD Opteron™ 6200 Series Processor"},
                {0x3E,"AMD Opteron™ 4200 Series Processor"},
                {0x3F,"AMD FX™ Series Processor"},
                {0x40,"MIPS Family"},
                {0x41,"MIPS R4000"},
                {0x42,"MIPS R4200"},
                {0x43,"MIPS R4400"},
                {0x44,"MIPS R4600"},
                {0x45,"MIPS R10000"},
                {0x46,"AMD C-Series Processor"},
                {0x47,"AMD E-Series Processor"},
                {0x48,"AMD A-Series Processor"},
                {0x49,"AMD G-Series Processor"},
                {0x4A,"AMD Z-Series Processor"},
                {0x4B,"AMD R-Series Processor"},
                {0x4C,"AMD Opteron™ 4300 Series Processor"},
                {0x4D,"AMD Opteron™ 6300 Series Processor"},
                {0x4E,"AMD Opteron™ 3300 Series Processor"},
                {0x4F,"AMD FirePro™ Series Processor"},
                {0x50,"SPARC Family"},
                {0x51,"SuperSPARC"},
                {0x52,"microSPARC II"},
                {0x53,"microSPARC IIep"},
                {0x54,"UltraSPARC"},
                {0x55,"UltraSPARC II"},
                {0x56,"UltraSPARC Iii"},
                {0x57,"UltraSPARC III"},
                {0x58,"UltraSPARC IIIi"},
                //0x59-0x5F
                {0x60,"68040 Family"},
                {0x61,"68xxx"},
                {0x62,"68000"},
                {0x63,"68010"},
                {0x64,"68020"},
                {0x65,"68030"},
                {0x66,"AMD Athlon(TM) X4 Quad-Core Processor Family"},
                {0x67,"AMD Opteron(TM) X1000 Series Processor"},
                {0x68,"AMD Opteron(TM) X2000 Series APU"},
                {0x69,"AMD Opteron(TM) A-Series Processor"},
                {0x6A,"AMD Opteron(TM) X3000 Series APU"},
                {0x6B,"AMD Zen Processor Family"},
                //0x6C-0x6F
                {0x70,"Hobbit Family"},
                //0x71-0x77
                {0x78,"Crusoe™ TM5000 Family"},
                {0x79,"Crusoe™ TM3000 Family"},
                {0x7A,"Efficeon™ TM8000 Family"},
                //0x7B-0x7F
                {0x80,"Weitek"},
                {0x81,"Unknown"},
                {0x82,"Itanium™ processor"},
                {0x83,"AMD Athlon™ 64 Processor Family"},
                {0x84,"AMD Opteron™ Processor Family"},
                {0x85,"AMD Sempron™ Processor Family"},
                {0x86,"AMD Turion™ 64 Mobile Technology"},
                {0x87,"Dual-Core AMD Opteron™ Processor Family"},
                {0x88,"AMD Athlon™ 64 X2 Dual-Core Processor Family"},
                {0x89,"AMD Turion™ 64 X2 Mobile Technology"},
                {0x8A,"Quad-Core AMD Opteron™ Processor Family"},
                {0x8B,"Third-Generation AMD Opteron™ Processor Family"},
                {0x8C,"AMD Phenom™ FX Quad-Core Processor Family"},
                {0x8D,"AMD Phenom™ X4 Quad-Core Processor Family"},
                {0x8E,"AMD Phenom™ X2 Dual-Core Processor Family"},
                {0x8F,"AMD Athlon™ X2 Dual-Core Processor Family"},
                {0x90,"PA-RISC Family"},
                {0x91,"PA-RISC 8500"},
                {0x92,"PA-RISC 8000"},
                {0x93,"PA-RISC 7300LC"},
                {0x94,"PA-RISC 7200"},
                {0x95,"PA-RISC 7100LC"},
                {0x96,"PA-RISC 7100"},
                //0x97-0x9F
                {0xA0,"V30 Family"},
                {0xA1,"Quad-Core Intel® Xeon® processor 3200 Series"},
                {0xA2,"Dual-Core Intel® Xeon® processor 3000 Series"},
                {0xA3,"Quad-Core Intel® Xeon® processor 5300 Series"},
                {0xA4,"Dual-Core Intel® Xeon® processor 5100 Series"},
                {0xA5,"Dual-Core Intel® Xeon® processor 5000 Series"},
                {0xA6,"Dual-Core Intel® Xeon® processor LV"},
                {0xA7,"Dual-Core Intel® Xeon® processor ULV"},
                {0xA8,"Dual-Core Intel® Xeon® processor 7100 Series"},
                {0xA9,"Quad-Core Intel® Xeon® processor 5400 Series"},
                {0xAA,"Quad-Core Intel® Xeon® processor"},
                {0xAB,"Dual-Core Intel® Xeon® processor 5200 Series"},
                {0xAC,"Dual-Core Intel® Xeon® processor 7200 Series"},
                {0xAD,"Quad-Core Intel® Xeon® processor 7300 Series"},
                {0xAE,"Quad-Core Intel® Xeon® processor 7400 Series"},
                {0xAF,"Multi-Core Intel® Xeon® processor 7400 Series"},
                {0xB0,"Pentium® III Xeon™ processor"},
                {0xB1,"Pentium® III Processor with Intel® SpeedStep™ Technology"},
                {0xB2,"Pentium® 4 Processor"},
                {0xB3,"Intel® Xeon® processor"},
                {0xB4,"AS400 Family"},
                {0xB5,"ntel® Xeon™ processor MP"},
                {0xB6,"AMD Athlon™ XP Processor Family"},
                {0xB7,"AMD Athlon™ MP Processor Family"},
                {0xB8,"Intel® Itanium® 2 processor"},
                {0xB9,"Intel® Pentium® M processor"},
                {0xBA,"Intel® Celeron® D processor"},
                {0xBB,"Intel® Pentium® D processor"},
                {0xBC,"Intel® Pentium® Processor Extreme Edition"},
                {0xBD,"Intel® Core™ Solo Processor"},
                //0xBE
                {0xBF,"Intel® Core™ 2 Duo Processor"},
                {0xC0,"Intel® Core™ 2 Solo processor"},
                {0xC1,"Intel® Core™ 2 Extreme processor"},
                {0xC2,"Intel® Core™ 2 Quad processor"},
                {0xC3,"Intel® Core™ 2 Extreme mobile processor"},
                {0xC4,"Intel® Core™ 2 Duo mobile processor"},
                {0xC5,"Intel® Core™ 2 Solo mobile processor"},
                {0xC6,"Intel® Core™ i7 processor"},
                {0xC7,"Dual-Core Intel® Celeron® processor"},
                {0xC8,"IBM390 Family"},
                {0xC9,"G4"},
                {0xCA,"G5"},
                {0xCB,"ESA/390 G6"},
                {0xCC,"z/Architecture base"},
                {0xCD,"Intel® Core™ i5 processor"},
                {0xCE,"Intel® Core™ i3 processor"},
                {0xCF,"Intel® Core™ i9 processor"},
                //0xD0-0xD1
                {0xD2,"VIA C7™-M Processor Family"},
                {0xD3,"VIA C7™-D Processor Family"},
                {0xD4,"VIA C7™ Processor Family"},
                {0xD5,"VIA Eden™ Processor Family"},
                {0xD6,"Multi-Core Intel® Xeon® processor"},
                {0xD7,"Dual-Core Intel® Xeon® processor 3xxx Series"},
                {0xD8,"Quad-Core Intel® Xeon® processor 3xxx Series"},
                {0xD9,"VIA Nano™ Processor Family"},
                {0xDA,"Dual-Core Intel® Xeon® processor 5xxx Serie"},
                {0xDB,"Quad-Core Intel® Xeon® processor 5xxx Series"},
                //0xDC
                {0xDD,"Dual-Core Intel® Xeon® processor 7xxx Series"},
                {0xDE,"Quad-Core Intel® Xeon® processor 7xxx Serie"},
                {0xDF,"Multi-Core Intel® Xeon® processor 7xxx Serie"},
                {0xE0,"Multi-Core Intel® Xeon® processor 3400 Series"},
                //0xE1-0xE3
                {0xE4,"AMD Opteron™ 3000 Series Processor"},
                {0xE5,"AMD Sempron™ II Processor"},
                {0xE6,"Embedded AMD Opteron™ Quad-Core Processor Family"},
                {0xE7,"AMD Phenom™ Triple-Core Processor Family"},
                {0xE8,"AMD Turion™ Ultra Dual-Core Mobile Processor Famil"},
                {0xE9,"AMD Turion™ Dual-Core Mobile Processor Family"},
                {0xEA,"AMD Athlon™ Dual-Core Processor Family"},
                {0xEB,"AMD Sempron™ SI Processor Family"},
                {0xEC,"AMD Phenom™ II Processor Family"},
                {0xED,"AMD Athlon™ II Processor Family"},
                {0xEE,"Six-Core AMD Opteron™ Processor Family"},
                {0xEF,"AMD Sempron™ M Processor Family"},
                //0xF0-0xF9
                {0xFA,"i860"},
                {0xFB,""},
                //0xFC-0xFD
                {0xFE,"i960"}
                //0xFF
            };
            const auto& found {family_map.find(key)};
            if(found!=family_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get processor family-2
    const auto& family_2_get{[](unsigned short key){
            const std::map<unsigned short,std::string>& family_map{
                {0x100,"ARMv7"},
                {0x101,"ARMv8"},
                {0x102,"ARMv9"},
                {0x103,"Reserved for future use by ARM"},
                {0x104,"SH-3"},
                {0x105,"SH-4"},
                {0x118,"ARM"},
                {0x119,"StrongARM"},
                {0x12C,"6x86"},
                {0x12D,"MediaGX"},
                {0x12E,"MII"},
                {0x140,"WinChip"},
                {0x15E,"DSP"},
                {0x1F4,"Video Processor"},
                //0x200-0x2FF available except folowing
                {0x200,"RISC-V RV32"},
                {0x201,"RISC-V RV64"},
                {0x202,"RISC-V RV128"},
                {0x258,"LoongArch"},
                {0x259,"Loongson™ 1 Processor Family"},
                {0x25A,"Loongson™ 2 Processor Family"},
                {0x25B,"Loongson™ 3 Processor Family"},
                {0x25C,"Loongson™ 2K Processor Family"},
                {0x25D,"Loongson™ 3A Processor Family"},
                {0x25E,"Loongson™ 3B Processor Family"},
                {0x25F,"Loongson™ 3C Processor Family"},
                {0x260,"Loongson™ 3D Processor Family"},
                {0x261,"Loongson™ 3E Processor Family"},
                {0x262,"Dual-Core Loongson™ 2K Processor 2xxx Series"},
                {0x26C,"Quad-Core Loongson™ 3A Processor 5xxx Series"},
                {0x26D,"Multi-Core Loongson™ 3A Processor 5xxx Series"},
                {0x26E,"Quad-Core Loongson™ 3B Processor 5xxx Series"},
                {0x26F,"Multi-Core Loongson™ 3B Processor 5xxx Series"},
                {0x270,"Multi-Core Loongson™ 3C Processor 5xxx Series"},
                {0x271,"Multi-Core Loongson™ 3D Processor 5xxx Series"}
            };
            const auto& found {family_map.find(key)};
            if(found!=family_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get processor characteristics
    const auto& characteristics_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& chars_map{
                {0x00,"Reserved"},
                {0x02,"Unknown"},
                {0x04,"64-bit Capable"},
                {0x08,"Multi-Core"},
                {0x10,"Hardware Thread"},
                {0x20,"Execute Protection"},
                {0x40,"Enhanced Virtualization"},
                {0x80,"Power/Performance Control"},
                {0x100,"128-bit Capable"},
                {0x200,"Arm64 SoC ID"}
            };
            std::vector<std::string> out {};
            for(const auto& pair: chars_map){
                if((key & pair.first)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get cpu status
    const auto& status_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& status_map{
                {0x00,"Unknown"},
                {0x01,"CPU Enabled"},
                {0x02,"CPU Disabled by User"},
                {0x03,"CPU Disabled by BIOS (POST Error)"},
                {0x04,"CPU is Idle"},
                {0x05,"Reserved"},
                {0x06,"Reserved"},
                {0x07,"Other"}
            };

            for(const auto& pair: status_map){
                if((key & 0x0F) & pair.first){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    //get populated status
    const auto& populated_get{[](unsigned char key){
            return (key & 0x40) ? std::string {"CPU Socket Populated"} :
                                  std::string {"CPU Socket Unpopulated"};
        }
    };

    const int& socket_locator {dmi.data_.size() > 0x04 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x04))-1) : -1};

    std::string socket_designation {};
    if((socket_locator >=0) && dmi.strings_.size()>socket_locator){
        socket_designation=boost::trim_copy(dmi.strings_.at(socket_locator));
    }

    const std::string& processor_type {dmi.data_.size() > 0x05 ?
                    type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const int& processor_manufacturer_locator {dmi.data_.size() > 0x07 ?
                     (static_cast<unsigned char>(dmi.data_.at(0x07))-1) : -1};

    std::string processor_manufacturer {};
    if((processor_manufacturer_locator >=0) && dmi.strings_.size()>processor_manufacturer_locator){
        processor_manufacturer=boost::trim_copy(dmi.strings_.at(processor_manufacturer_locator));
    }

    std::string processor_id {""};
    if(dmi.data_.size()>0x0A){
        std::vector<char> id_data;
        id_data.assign(dmi.data_.begin()+0x08,dmi.data_.begin()+0x08+0x08);
        boost::algorithm::hex(id_data.begin(),id_data.end(),std::back_inserter(processor_id));
    }

    const int& version_locator {dmi.data_.size() > 0x10 ?
                     (static_cast<unsigned char>(dmi.data_.at(0x10))-1) : -1};

    std::string processor_version {};
    if((version_locator >=0) && dmi.strings_.size()>version_locator){
        processor_version=boost::trim_copy(dmi.strings_.at(version_locator));
    }

    const std::vector<std::string>& voltage (dmi.data_.size()>0x11 ?
                                    voltage_get(static_cast<unsigned char>(dmi.data_.at(0x11))) :
                                                 std::vector<std::string>{});

    const int& external_clock {dmi.data_.size()>0x13 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x13)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x12))) : 0};

    const int& max_speed {dmi.data_.size()>0x15 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x15)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x14))) : 0};

    const int& current_speed {dmi.data_.size()>0x17 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x17)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x16))) : 0};

    const int& status_key {dmi.data_.size()>0x18 ?
                    static_cast<unsigned char>(dmi.data_.at(0x18)) : -1};

    const std::string& status {status_get(status_key)};

    const std::string& populated_status {populated_get(status_key)};

    const std::string& processor_upgrade {dmi.data_.size()>0x19 ?
                    upgrade_get(static_cast<unsigned char>(dmi.data_.at(0x19))):
                    std::string {}};

    const int& l1_cache_handle {dmi.data_.size()>0x1B ?
                    static_cast<unsigned char>(dmi.data_.at(0x1B)) * 0x100 +
                    static_cast<unsigned char>(dmi.data_.at(0x1A)) : 0};

    const int& l2_cache_handle {dmi.data_.size()>0x1D ?
                    static_cast<unsigned char>(dmi.data_.at(0x1D)) * 0x100 +
                    static_cast<unsigned char>(dmi.data_.at(0x1C)) : 0};

    const int& l3_cache_handle {dmi.data_.size()>0x1F ?
                     static_cast<unsigned char>(dmi.data_.at(0x1F)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x1E)) : 0};

    const int& serial_locator {dmi.data_.size() > 0x20 ?
                 (static_cast<unsigned char>(dmi.data_.at(0x20))-1) : -1};

    std::string serial_number {};
    if((serial_locator >=0) && dmi.strings_.size()>serial_locator){
        serial_number=boost::trim_copy(dmi.strings_.at(serial_locator));
    }

    const int& asset_locator {dmi.data_.size() > 0x21 ?
                 (static_cast<unsigned char>(dmi.data_.at(0x21))-1) : -1};

    std::string asset_tag {};
    if((asset_locator >=0) && dmi.strings_.size()>asset_locator){
        asset_tag=boost::trim_copy(dmi.strings_.at(asset_locator));
    }

    const int& part_locator {dmi.data_.size() > 0x22 ?
                 (static_cast<unsigned char>(dmi.data_.at(0x22))-1) : -1};

    std::string part_number {};
    if((part_locator >=0) && dmi.strings_.size()>part_locator){
        part_number=boost::trim_copy(dmi.strings_.at(part_locator));
    }

    const int& core_count {dmi.data_.size()>0x23 ?
                    static_cast<unsigned char>(dmi.data_.at(0x23)) : 0};

    const int& core_enabled {dmi.data_.size()>0x24 ?
                    static_cast<unsigned char>(dmi.data_.at(0x24)) : 0};

    const int& thread_count {dmi.data_.size()>0x25 ?
                    static_cast<unsigned char>(dmi.data_.at(0x25)) : 0};

    const std::vector<std::string>& processor_characteristics(dmi.data_.size()>0x26 ?
                                          characteristics_get(static_cast<unsigned char>(dmi.data_.at(0x26))) :
                                          std::vector<std::string>{});

    const std::string& processor_family (dmi.data_.size()>0x28 ?
                                         family_get(static_cast<unsigned char>(dmi.data_.at(0x28))) :
                                         std::string {});

    const int& processor_family_2_key {dmi.data_.size()>0x29 ?
                    ((static_cast<unsigned short>(dmi.data_.at(0x29)))* 0x100 +
                      static_cast<unsigned char>(dmi.data_.at(0x28))) : 0};

    const std::string& processor_family_2 {family_2_get(processor_family_2_key)};

    const boost::json::object& out_object{
        {"object_type", "processor_information"},
        {"socket_designation", socket_designation},
        {"processor_type", processor_type},
        {"processor_manufacturer", processor_manufacturer},
        {"processor_id", processor_id},
        {"processor_version", processor_version},
        {"voltage", boost::join(voltage, ", ")},
        {"external_clock", external_clock},
        {"max_speed", max_speed},
        {"current_speed", current_speed},
        {"status", status},
        {"populated_status", populated_status},
        {"processor_upgrade", processor_upgrade},
        {"l1_cache_handle", l1_cache_handle},
        {"l2_cache_handle", l2_cache_handle},
        {"l3_cache_handle", l3_cache_handle},
        {"serial_number", serial_number},
        {"asset_tag", asset_tag},
        {"part_number", part_number},
        {"core_count", core_count},
        {"core_enabled", core_enabled},
        {"thread_count", thread_count},
        {"processor_characteristics", boost::join(processor_characteristics, ",")},
        {"processor_family", processor_family},
        {"processor_family_2", processor_family_2}
    };
    return out_object;
}

//Type 5, Obsolete
boost::json::object decoder::memory_controller_information(const structure &dmi)
{
    //get error detecting
    const auto& error_detecting_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& error_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"None"},
                {0x04,"8-bit Parity"},
                {0x05,"32-bit ECC"},
                {0x06,"64-bit ECC"},
                {0x07,"128-bit ECC"},
                {0x08,"CRC"}
            };
            const auto& found {error_map.find(key)};
            if(found!=error_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get error correcting
    const auto& error_correcting_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& error_map{
                {0x01,"Unknown"},
                {0x02,"None"},
                {0x03,"Single-Bit Error Correcting"},
                {0x04,"Double-Bit Error Correcting"},
                {0x05,"Error Scrubbing"},{0x00,"Other"},
            };
            std::vector<std::string> out;
            for(const auto& pair: error_map){
                if((pair.first & key)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get supported/current interleave
    const auto& interleave_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& error_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"One-Way Interleave"},
                {0x04,"Two-Way Interleave"},
                {0x05,"Four-Way Interleave"},
                {0x06,"Eight-Way Interleave"},
                {0x07,"Sixteen-Way Interleave"}
            };
            const auto& found {error_map.find(key)};
            if(found!=error_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const std::string& error_detecting_method {dmi.data_.size()>0x04 ?
                    error_detecting_get(static_cast<unsigned char>(dmi.data_.at(0x04))) :
                    std::string {}};

    const std::vector<std::string>& error_correcting_capability {dmi.data_.size()>0x05 ?
                    error_correcting_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::vector<std::string> {}};

    const std::string& supported_interleave {dmi.data_.size()>0x06 ?
                    interleave_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                    std::string {}};

    const std::string& current_interleave {dmi.data_.size()>0x07 ?
                    interleave_get(static_cast<unsigned char>(dmi.data_.at(0x07))) :
                    std::string {}};

    const boost::json::object& out_object{
        {"object_type", "memory_controller_information"},
        {"error_detecting_method", error_detecting_method},
        {"error_correcting_capability", boost::join(error_correcting_capability, ", ")},
        {"supported_interleave", supported_interleave},
        {"current_interleave", current_interleave}
    };
    return out_object;
}

//Type 6, Obsolete
boost::json::object decoder::memory_module_information(const structure &dmi)
{
    //get memory type
    const auto& type_get{[](unsigned short key){
            const std::map<unsigned short,std::string>& type_map{
                {0x01, "Other"},
                {0x02, "Unknown"},
                {0x04, "Standard"},
                {0x08, "Fast Page Mode"},
                {0x10, "EDO"},
                {0x20, "Parity"},
                {0x40, "ECC"},
                {0x80, "SIMM"},
                {0x100,"DIMM"},
                {0x200,"Burst EDO"},
                {0x400,"SDRAM"}
            };
            std::vector<std::string> out;
            for(const auto& pair: type_map){
                if((key & pair.first)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get installed/enabled memory size
    const auto& size_get{[](unsigned char key){
            if(key==0x7D || key==0x7E || key==0x7F){
                return 0LL;
            }
            return static_cast<long long>(pow(2,key) * 1024 * 1024);
        }
    };

    const int& designation_locator {dmi.data_.size()>0x04 ?
                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1};
    const std::string& socket_designation {(designation_locator>=0) && (dmi.strings_.size()>designation_locator) ?
                    boost::trim_copy(dmi.strings_.at(designation_locator)) :
                    std::string {}};

    const int& bank_connections {dmi.data_.size()>0x05 ?
                    static_cast<unsigned char>(dmi.data_.at(0x05)) : 0};

    const int& current_speed {dmi.data_.size()>0x06 ?
                    static_cast<unsigned char>(dmi.data_.at(0x05)) : 0};

    const int& current_memory_type_key {dmi.data_.size()>0x08 ?
                static_cast<unsigned char>(dmi.data_.at(0x08)) * 0x100 +
                static_cast<unsigned char>(dmi.data_.at(0x07)) : 0};

    const std::vector<std::string>& current_memory_type {type_get(current_memory_type_key)};

    const int& installed_size_key {dmi.data_.size()>0x09 ?
                                   static_cast<unsigned char>(dmi.data_.at(0x09)) : 0};
    const long long& installed_size {size_get(installed_size_key)};

    const int& enabled_size_key {dmi.data_.size()>0x0A ?
                                   static_cast<unsigned char>(dmi.data_.at(0x0A)) : 0};
    const long long enabled_size {size_get(enabled_size_key)};

    const boost::json::object& out_object {
        {"object_type", "memory_module_information"},
        {"socket_designation", socket_designation},
        {"bank_connections", bank_connections},
        {"current_speed", (boost::format("%d ns")% current_speed).str()},
        {"current_memory_type", boost::join(current_memory_type,", ")},
        {"installed_size", installed_size},
        {"enabled_size", enabled_size}
    };
    return out_object;
}

//Type 7
boost::json::object decoder::cache_information(const structure &dmi)
{
    //get cache location for configuration
    const auto& location_get{[](unsigned short key){
            const unsigned char& sub_key {static_cast<unsigned char>(key & 0x60)};
            const std::map<unsigned char,std::string>& location_map {
                {0x00,"Internal"},
                {0x20,"External"},
                {0x40,"Reserved"},
                {0x60,"Unknown"}
            };
            const auto& found {location_map.find(sub_key)};
            if(found!=location_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get operation mode for cache configuration
    const auto mode_get{[](unsigned short key){
            const unsigned short& sub_key {static_cast<unsigned short>(key & 0x300)};
            const std::map<unsigned short,std::string>& mode_map{
                {0x000,"Write Through"},
                {0x100,"Write Back"},
                {0x200,"Varies with Memory Address"},
                {0x300,"Unknown"}
            };
            const auto& found {mode_map.find(sub_key)};
            if(found!=mode_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get cache configuration
    const auto& configuration_get{[&location_get, &mode_get](unsigned short key){
            std::vector<std::string> out;
            if(!key){
                return out;
            }

            const int& level_ {static_cast<unsigned char>(key>>13)};
            const std::string& level {(boost::format("Level: %d")
                                          % level_).str()};
            const std::string& socketed {(static_cast<unsigned char>(key & 0x08))!=0 ?
                            std::string {"Socketed"} : std::string {"Not Socketed"}};

            const std::string& location {location_get(key)};

            const std::string& enabled {static_cast<unsigned char>(key & 0x80)!=0 ?
                            std::string {"Enabled"} : std::string {"Disabled"}};

            const std::string& operation_mode {mode_get(key)};
            out.push_back(level);
            out.push_back(socketed);
            out.push_back(location);
            out.push_back(enabled);
            out.push_back(operation_mode);
            return out;
        }
    };

     //get max cache size
     const auto& maximum_cache_size_get{[](unsigned short key){
             const int& granularity {(key & 0x8000)==0 ? 1 : 64};
             return (key & 0x7FFF) * granularity;
         }
     };

     //get SRAM type
     const auto& sram_type_get {[](unsigned short key){
             const std::map<unsigned short,std::string>& type_map{
                 {0x01,"Other"},
                 {0x02,"Unknown"},
                 {0x04,"Non-Burst"},
                 {0x08,"Burst"},
                 {0x10,"Pipeline Burst"},
                 {0x20,"Synchronous"},
                 {0x40,"Asynchronous"}
             };
             for(const auto& pair: type_map){
                 if((pair.first & key)!=0){
                     return pair.second;
                 }
             }
             return std::string {};
         }
     };

     //get error correction type
     const auto& error_correction_type_get{[](unsigned char key){
             const std::map<unsigned char,std::string>& err_map {
                 {0x01,"Other"},
                 {0x02,"Unknown"},
                 {0x03,"None"},
                 {0x04,"Parity"},
                 {0x05,"Single-bit ECC"},
                 {0x06,"Multi-bit ECC"}
             };
             const auto& found {err_map.find(key)};
             if(found!=err_map.end()){
                 return found->second;
             }
             return std::string {};
         }
     };

     //get system cache type
     const auto& system_cache_type_get{[](unsigned char key){
             const std::map<unsigned char,std::string>& type_map {
                 {0x01,"Other"},
                 {0x02,"Unknown"},
                 {0x03,"Instruction"},
                 {0x04,"Data"},
                 {0x05,"Unified"}
             };
             const auto& found {type_map.find(key)};
             if(found!=type_map.end()){
                 return found->second;
             }
             return std::string {};
         }
     };

     //get associativity
     const auto& associativity_get{[](unsigned char key){
             const std::map<unsigned char,std::string>& type_map {
                 {0x01,"Other"},
                 {0x02,"Unknown"},
                 {0x03,"Direct Mapped"},
                 {0x04,"2-way Set-Associative"},
                 {0x05,"4-way Set-Associative"},
                 {0x06,"Fully Associative"},
                 {0x07,"8-way Set-Associative"},
                 {0x08,"16-way Set-Associative"},
                 {0x09,"12-way Set-Associative"},
                 {0x0A,"24-way Set-Associative"},
                 {0x0B,"32-way Set-Associative"},
                 {0x0C,"48-way Set-Associative"},
                 {0x0D,"64-way Set-Associative"},
                 {0x0E,"20-way Set-Associative"}
             };
             const auto& found {type_map.find(key)};
             if(found!=type_map.end()){
                 return found->second;
             }
             return std::string {};
         }
     };

     const int designation_locator {dmi.data_.size()>0x04 ?
                     static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1};

     const std::string& socket_designation {dmi.strings_.size()>designation_locator && designation_locator>=0 ?
                     boost::trim_copy(dmi.strings_.at(designation_locator)) :
                     std::string {}};

     const int& configuration_key {dmi.data_.size()>0x06 ?
                     ((static_cast<unsigned short>(dmi.data_.at(0x06)) * 0x100) +
                      static_cast<unsigned char>(dmi.data_.at(0x07))) : -1};

     const std::vector<std::string>& configuration {configuration_get(configuration_key)};

     const int& maximum_cache_size_key {dmi.data_.size()>0x08 ?
                     static_cast<unsigned char>(dmi.data_.at(0x08)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x07)) : 0};

     const int& maximum_cache_size {maximum_cache_size_get(maximum_cache_size_key)};

     const int& installed_cache_size_key {dmi.data_.size()>0x0A ?
                     static_cast<unsigned char>(dmi.data_.at(0x0A)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x09)) : 0};

     const int& installed_cache_size {maximum_cache_size_get(installed_cache_size_key)};

     const int& supported_sram_type_key {dmi.data_.size()>0x0C ?
                     static_cast<unsigned char>(dmi.data_.at(0x0C)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0B)) : 0};

     const std::string& supported_sram_type {sram_type_get(supported_sram_type_key)};

     const int& current_sram_type_key {dmi.data_.size()>0x0E ?
                      static_cast<unsigned char>(dmi.data_.at(0x0E)) * 0x100 +
                      static_cast<unsigned char>(dmi.data_.at(0x0D)) : 0};

     const std::string& current_sram_type {sram_type_get(current_sram_type_key)};

     const int& cache_speed_ {dmi.data_.size()>0x0F ?
                     static_cast<unsigned char>(dmi.data_.at(0x0F)) :
                     0};
     const std::string& cache_speed {(boost::format("%d ns")
                                      % cache_speed_).str()};;

     const std::string& error_correction_type {dmi.data_.size()>0x10 ?
                     error_correction_type_get(static_cast<unsigned char>(dmi.data_.at(0x10))):
                     std::string {}};

     const std::string& system_cache_type {dmi.data_.size()>0x11 ?
                     system_cache_type_get(static_cast<unsigned char>(dmi.data_.at(0x11))):
                     std::string {}};

     const std::string& associativity {dmi.data_.size()>0x12 ?
                     associativity_get(static_cast<unsigned char>(dmi.data_.at(0x12))) :
                     std::string {}};

     const boost::json::object& out_object{
         {"object_type", "cache_information"},
         {"socket_designation", socket_designation},
         {"configuration", boost::join(configuration,", ")},
         {"maximum_cache_size", maximum_cache_size},
         {"installed_cache_size", installed_cache_size},
         {"supported_sram_type", supported_sram_type},
         {"current_sram_type", current_sram_type},
         {"cache_speed", cache_speed},
         {"error_correction_type", error_correction_type},
         {"system_cache_type", system_cache_type},
         {"associativity", associativity}
     };
     return out_object;
}

//Type 8
boost::json::object decoder::port_connector_information(const structure &dmi)
{
    //get external connector type
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x00,"None"},
                {0x01,"Centronics"},
                {0x02,"Mini Centronics"},
                {0x03,"Proprietary"},
                {0x04,"DB-25 pin male"},
                {0x05,"DB-25 pin female"},
                {0x06,"DB-15 pin male"},
                {0x07,"DB-15 pin female"},
                {0x08,"DB-9 pin male"},
                {0x09,"DB-9 pin female"},
                {0x0A,"RJ-11"},
                {0x0b,"RJ-45"},
                {0x0C,"50-pin MiniSCSI"},
                {0x0D,"Mini-DIN"},
                {0x0E,"Micro-DIN"},
                {0x0F,"PS/2"},
                {0x10,"Infrared"},
                {0x11,"HP-HIL"},
                {0x12,"Access Bus (USB)"},
                {0x13,"SSA SCSI"},
                {0x14,"Circular DIN-8 male"},
                {0x15,"Circular DIN-8 female"},
                {0x16,"On Board IDE"},
                {0x17,"On Board Floppy"},
                {0x18,"9-pin Dual Inline (pin 10 cut)"},
                {0x19,"25-pin Dual Inline (pin 26 cut)"},
                {0x1A,"50-pin Dual Inline"},
                {0x1B,"68-pin Dual Inline"},
                {0x1C,"On Board Sound Input from CD-ROM"},
                {0x1D,"Mini-Centronics Type-14"},
                {0x1E,"Mini-Centronics Type-26"},
                {0x1F,"Mini-jack (headphones)"},
                {0x20,"BNC"},
                {0x21,"1394"},
                {0x22,"SAS/SATA Plug Receptacle"},
                {0x23,"USB Type-C Receptacle"},
                {0xA0,"PC-98"},
                {0xA1,"PC-98Hireso"},
                {0xA2,"PC-H98"},
                {0xA3,"PC-98Note"},
                {0xA4,"PC-98Full"},
                {0xFF,"Other"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get port type
    const auto& port_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& port_map{
                {0x00,"None"},
                {0x01,"Parallel Port XT/AT Compatible"},
                {0x02,"Parallel Port PS/2"},
                {0x03,"Parallel Port ECP"},
                {0x04,"Parallel Port EPP"},
                {0x05,"Parallel Port ECP/EPP"},
                {0x06,"Serial Port XT/AT Compatible"},
                {0x07,"Serial Port 16450 Compatible"},
                {0x08,"Serial Port 16550 Compatible"},
                {0x09,"Serial Port 16550A Compatible"},
                {0x0A,"SCSI Port"},
                {0x0B,"MIDI Port"},
                {0x0C,"Joy Stick Port"},
                {0x0D,"Keyboard Port"},
                {0x0E,"Mouse Port"},
                {0x0F,"SSA SCSI"},
                {0x10,"USB"},
                {0x11,"FireWire (IEEE P1394)"},
                {0x12,"PCMCIA Type I2"},
                {0x13,"PCMCIA Type II"},
                {0x14,"PCMCIA Type III"},
                {0x15,"Card bus"},
                {0x16,"Access Bus Port"},
                {0x17,"SCSI II"},
                {0x18,"SCSI Wide"},
                {0x19,"PC-98"},
                {0x1A,"PC-98-Hireso"},
                {0x1B,"PC-H98"},
                {0x1C,"Video Port"},
                {0x1D,"Audio Port"},
                {0x1E,"Modem Port"},
                {0x1F,"Network Port"},
                {0x20,"SATA"},
                {0x21,"SAS"},
                {0x22,"MFDP (Multi-Function Display Port)"},
                {0x23,"Thunderbolt"},
                {0xA0,"8251 Compatible"},
                {0xA1,"8251 FIFO Compatible"},
                {0xFF,"Other"}
            };
            const auto& found {port_map.find(key)};
            if(found!=port_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& internal_reference_locator (dmi.data_.size()>0x04 ?
                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);

    const std::string& internal_reference_designator ((internal_reference_locator>=0) && (dmi.strings_.size()>internal_reference_locator) ?
                boost::trim_copy(dmi.strings_.at(internal_reference_locator)) :
                                                      std::string {});

    const std::string& internal_connector_type (dmi.data_.size()>0x05 ?
                                                type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                                std::string {});

    const int& external_reference_locator (dmi.data_.size()>0x06 ?
                    static_cast<unsigned char>(dmi.data_.at(0x06))-1 : -1);

    const std::string& external_reference_designator ((external_reference_locator>=0) && (dmi.strings_.size()>external_reference_locator) ?
                boost::trim_copy(dmi.strings_.at(external_reference_locator)) :
                                                      std::string {});

    const std::string& external_connector_type (dmi.data_.size()>0x07 ?
                                                type_get(static_cast<unsigned char>(dmi.data_.at(0x07))) :
                                                std::string {});

    const std::string& port_type (dmi.data_.size()>0x08 ?
                                  port_get(static_cast<unsigned char>(dmi.data_.at(0x08))) :
                                  std::string {});

    const boost::json::object& out_object {
        {"object_type", "port_connector_information"},
        {"internal_reference_designator", internal_reference_designator},
        {"internal_connector_type", internal_connector_type},
        {"external_reference_designator", external_reference_designator},
        {"external_connector_type", external_connector_type},
        {"port_type", port_type}
    };
    return out_object;
}

//Type 9
boost::json::object decoder::system_slot_information(const structure &dmi)
{
    //get slot type
    const auto& slot_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"ISA"},
                {0x04,"MCA"},
                {0x05,"EISA"},
                {0x06,"PCI"},
                {0x07,"PC Card (PCMCIA)"},
                {0x08," VL-VESA"},
                {0x09,"Proprietary"},
                {0x0A,"Processor Card Slot"},
                {0x0b,"Proprietary Memory Card Slot"},
                {0x0c,"I/O Riser Card Slo"},
                {0x0d,"NuBus"},
                {0x0e,"PCI – 66MHz Capable"},
                {0x0f,"AGP"},
                {0x10,"AGP 2X"},
                {0x11,"AGP 4X"},
                {0x12,"PCI-X"},
                {0x13,"AGP 8X"},
                {0x14,"M.2 Socket 1-DP (Mechanical Key A)"},
                {0x15,"M.2 Socket 1-SD (Mechanical Key E)"},
                {0x16,"M.2 Socket 2 (Mechanical Key B)"},
                {0x17,"M.2 Socket 3 (Mechanical Key M)"},
                {0x18,"MXM Type I"},
                {0x19,"MXM Type II"},
                {0x1a,"MXM Type III (standard connector)"},
                {0x1b,"MXM Type III (HE connector)"},
                {0x1c,"MXM Type IV"},
                {0x1d,"MXM 3.0 Type A"},
                {0x1e,"MXM 3.0 Type B"},
                {0x1f,"PCI Express Gen 2 SFF-8639 (U.2)"},
                {0x20,"PCI Express Gen 3 SFF-8639 (U.2)"},
                {0x21,"PCI Express Mini 52-pin (CEM spec. 2.0)"},
                {0x22,"PCI Express Mini 52-pin (CEM spec. 2.0)"},
                {0x23,"PCI Express Mini 76-pin (CEM spec. 2.0)"},
                {0x24,"PCI Express Gen 4 SFF-8639 (U.2)"},
                {0x25,"PCI Express Gen 5 SFF-8639 (U.2)"},
                {0x26,"OCP NIC 3.0 Small Form Factor (SFF)"},
                {0x27,"OCP NIC 3.0 Large Form Factor (LFF)"},
                {0x28,"OCP NIC Prior to 3.0"},
                {0x30,"CXL Flexbus 1.0"},
                {0xa0,"PC-98/C20"},
                {0xa1,"PC-98/C24"},
                {0xa2,"PC-98/E"},
                {0xa3,"PC-98/Local Bus"},
                {0xa4,"PC-98/Card"},
                {0xa5,"PCI Express (see note below)"},
                {0xa6,"PCI Express x1"},
                {0xa7,"PCI Express x2"},
                {0xa8,"PCI Express x4"},
                {0xa9,"PCI Express x8"},
                {0xaa,"PCI Express x16"},
                {0xab,"PCI Express Gen 2"},
                {0xac,"PCI Express Gen 2 x1"},
                {0xad,"PCI Express Gen 2 x2"},
                {0xae,"PCI Express Gen 2 x4"},
                {0xaf,"PCI Express Gen 2 x8"},
                {0xb0,"PCI Express Gen 2 x16"},
                {0xb1,"PCI Express Gen 3"},
                {0xb2,"PCI Express Gen 3 x1"},
                {0xb3,"PCI Express Gen 3 x2"},
                {0xb4,"PCI Express Gen 3 x4"},
                {0xb5,"PCI Express Gen 3 x8"},
                {0xb6,"PCI Express Gen 3 x16"},
                {0xb7,"PCI Express Gen 4"},
                {0xb8,"PCI Express Gen 4 x1"},
                {0xb9,"PCI Express Gen 4 x2"},
                {0xba,"PCI Express Gen 4 x4"},
                {0xbb,"PCI Express Gen 4 x4"},
                {0xbc,"PCI Express Gen 4 x8"},
                {0xbd,"PCI Express Gen 4 x16"},
                {0xbe,"PCI Express Gen 5"},
                {0xbf,"PCI Express Gen 5 x2"},
                {0xc0,"PCI Express Gen 5 x2"},
                {0xc1,"PCI Express Gen 5 x4"},
                {0xc2,"PCI Express Gen 5 x8"},
                {0xc3,"PCI Express Gen 5 x16"},
                {0xc4,"PCI Express Gen 6 and Beyond"},
                {0xc5,"Enterprise and Datacenter 1U E1 Form Factor Slot (EDSFF E1.S, E1.L)"},
                {0xc6,"Enterprise and Datacenter 3' E3 Form Factor Slot (EDSFF E3.S, E3.L)"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get slot data bus width
    const auto& data_bus_width_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& width_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"8 bit"},
                {0x04,"16 bit"},
                {0x05,"32 bit"},
                {0x06,"64 bit"},
                {0x07,"128 bit"},
                {0x08,"1x or x1"},
                {0x09,"2x or x2"},
                {0x0A,"4x or x4"},
                {0x0B,"8x or x8"},
                {0x0C,"12x or x12"},
                {0x0D,"16x or x16"},
                {0x0E,"32x or x32"}
            };
            const auto& found {width_map.find(key)};
            if(found!=width_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get slot usage
    const auto& usage_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& usage_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Available"},
                {0x04,"In use"},
                {0x05,"Unavailable"}
            };
            const auto& found {usage_map.find(key)};
            if(found!=usage_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get slot length
    const auto& length_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& length_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Short Length"},
                {0x04,"Long Length"},
                {0x05,"2.5' drive form factor"},
                {0x06,"3.5' drive form factor"}
            };
            const auto& found {length_map.find(key)};
            if(found!=length_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get slot characteristics 1
    const auto& chars_1_get{[](unsigned char key){
            const std::map<unsigned char,std::string> chars_map{
                {0x01,"Unknown"},
                {0x02,"Provides 5.0 volts"},
                {0x04,"Provides 3.3 volts"},
                {0x08,"Slot’s opening is shared with another slot (for example, PCI/EISA shared slot)"},
                {0x10,"PC Card slot supports PC Card-16."},
                {0x20,"PC Card slot supports CardBus"},
                {0x40,"PC Card slot supports Zoom Video"},
                {0x80,"PC Card slot supports Modem Ring Resume"}
            };

            std::vector<std::string> out;
            for(const auto& pair: chars_map){
                if((pair.first & key)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get slot characteristics 2
    const auto& chars_2_get{[](unsigned char key){
            const std::map<unsigned char,std::string> chars_map{
                {0x01,"PCI slot supports Power Management Event (PME#) signal"},
                {0x02,"Slot supports hot-plug devices"},
                {0x04,"PCI slot supports SMBus signal"},
                {0x08,"PCIe slot supports bifurcation"},
                {0x10,"Slot supports async/surprise removal"},
                {0x20,"Flexbus slot, CXL 1.0 capable"},
                {0x40,"Flexbus slot, CXL 2.0 capable"},
                {0x80,"Reserved"}
            };

            std::vector<std::string> out;
            for(const auto& pair: chars_map){
                if((pair.first & key)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get slot physical width
    const auto& physical_width_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& width_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"8 bit"},
                {0x04,"16 bit"},
                {0x05,"32 bit"},
                {0x06,"64 bit"},
                {0x07,"128 bit"},
                {0x08,"1x or x1"},
                {0x09,"2x or x2"},
                {0x0A,"4x or x4"},
                {0x0B," 8x or x8"},
                {0x0C,"12x or x12"},
                {0x0D,"16x or x16"},
                {0x0E,"32x or x32"}
            };

            const auto& found {width_map.find(key)};
            if(found!=width_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& slot_designation_locator (dmi.data_.size()>0x04 ?
                                         static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);
    const std::string& slot_designation (dmi.strings_.size()>slot_designation_locator && slot_designation_locator>=0 ?
                                         boost::trim_copy(dmi.strings_.at(slot_designation_locator)) :
                                                                   std::string {});

    const std::string& slot_type (dmi.data_.size()>0x05 ?
                                  slot_type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                                std::string {});

    const std::string& slot_data_bus_width (dmi.data_.size()>0x06 ?
                                  data_bus_width_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                                                std::string {});

    const std::string& current_usage (dmi.data_.size()>0x07 ?
                                  usage_get(static_cast<unsigned char>(dmi.data_.at(0x07))) :
                                          std::string {});

    const std::string& slot_length (dmi.data_.size()>0x08 ?
                                  length_get(static_cast<unsigned char>(dmi.data_.at(0x08))) :
                                        std::string {});

    const int& slot_id {dmi.data_.size()>0x0A ?
                    (static_cast<unsigned short>(dmi.data_.at(0x0A)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x09))) : -1};

    const std::vector<std::string>& slot_characteristics_1 {dmi.data_.size()>0x0B ?
                    chars_1_get(static_cast<unsigned char>(dmi.data_.at(0x0B))) :
                    std::vector<std::string>{}};

    const int& segment_group_number {dmi.data_.size()>0x0E ?
                    (static_cast<unsigned short>(dmi.data_.at(0x0E)) * 0x100 +
                      static_cast<unsigned char>(dmi.data_.at(0x0D))) : 0};

    const int& bus_number {dmi.data_.size()>0x0F ?
                    static_cast<unsigned char>(dmi.data_.at(0x0F)) : 0};

    const int& device_function_number {dmi.data_.size()>0x10 ?
                    static_cast<unsigned char>(dmi.data_.at(0x10)) : 0};

    const int& data_bus_width {dmi.data_.size()>0x11 ?
                    static_cast<unsigned char>(dmi.data_.at(0x11)) : 0};

    const int& peer_grouping_count {dmi.data_.size()>0x12 ?
                    static_cast<unsigned char>(dmi.data_.at(0x12)) : 0};

    const int& peer_groups {dmi.data_.size()>0x13 ?
                    static_cast<unsigned char>(dmi.data_.at(0x13)) : 0};

    const std::vector<std::string>& slot_characteristics_2 {dmi.data_.size()>0x0C ?
                    chars_2_get(static_cast<unsigned char>(dmi.data_.at(0x0C))) :
                    std::vector<std::string>{}};

    const std::string& slot_physical_width {dmi.data_.size()>0x14 ?
                    physical_width_get(static_cast<unsigned char>(dmi.data_.at(0x14))) :
                    std::string {}};

    const boost::json::object& out_object {
        {"object_type", "system_slot_information"},
        {"slot_type", slot_type},
        {"slot_designation", slot_designation},
        {"slot_data_bus_width", slot_data_bus_width},
        {"current_usage", current_usage},
        {"slot_length", slot_length},
        {"slot_id", slot_id},
        {"slot_characteristics_1", boost::join(slot_characteristics_1,", ")},
        {"slot_characteristics_2", boost::join(slot_characteristics_2,", ")},
        {"segment_group_number", segment_group_number},
        {"bus_number", bus_number},
        {"device_function_number", device_function_number},
        {"data_bus_width", data_bus_width},
        {"peer_groups_count", peer_grouping_count},
        {"peer_groups", peer_groups},
        {"slot_physical_width", slot_physical_width}
    };
    return out_object;

}

//Type 10 Obsolete
boost::json::object decoder::onboard_device_information(const structure &dmi)
{
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Video"},
                {0x04,"SCSI Controller"},
                {0x05,"Ethernet"},
                {0x06,"Token Ring"},
                {0x07,"Sound"},
                {0x08,"PATA Controller"},
                {0x09,"SATA Controller"},
                {0x0A,"SAS Controller"}
            };

            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const boost::json::object& out_object{
        {"object_type", "onboard_device_information"},
    };
    return out_object;
}

//Type 11
boost::json::object decoder::oem_strings(const structure &dmi)
{
    boost::json::array oem_array;
    oem_array.insert(oem_array.begin(),dmi.strings_.begin(),dmi.strings_.end());
    const boost::json::object& out_object {
        {"object_type", "oem_strings"},
        {"oem_strings",oem_array}
    };
    return out_object;
}

//Type 12
boost::json::object decoder::system_configuration_options(const structure &dmi)
{
    boost::json::array sc_options;
    sc_options.insert(sc_options.begin(),dmi.strings_.begin(),dmi.strings_.end());
    const boost::json::object& out_object {
        {"object_type","system_configuration_options"},
        {"system_configuration_options", sc_options}
    };
    return out_object;
}

//Type 13
boost::json::object decoder::bios_language_information(const structure &dmi)
{
    boost::json::array bios_languages;
    bios_languages.insert(bios_languages.begin(),dmi.strings_.begin(),dmi.strings_.end());
    const boost::json::object& out_object {
        {"object_type","bios_language_information"},
        {"installable_languages", bios_languages}
    };
    return out_object;
}

//Type 14
void decoder::group_associations(const structure &dmi)
{
    int begin_ {0x04};
    const int group_size {0x03};
    if(dmi.data_.size()==begin_ || dmi.data_.size()<(begin_+group_size)){
        return;
    }

    for(int i=begin_;i<dmi.data_.size(); i+=group_size){
        //check if we can read three byte block next
        if(dmi.data_.size()<=(i+group_size)){
            break;
        }

        const int& group_name_locator {static_cast<unsigned char>(dmi.data_.at(i)-1)};
        const std::string& group_name {group_name_locator>=0 && dmi.strings_.size()>group_name_locator ?
                        boost::trim_copy(dmi.strings_.at(group_name_locator)) :
                        std::string {"Unknown"}};

        const int& item_type {static_cast<unsigned char>(dmi.data_.at(i+1))};
        const int& item_handle {static_cast<unsigned char>(dmi.data_.at(i+2))};

        std::for_each(structure_list_.begin(),structure_list_.end(),[&item_type, &item_handle,this](const structure& dmi){
            if(dmi.type_==item_type){
                const boost::json::object& json {decode_structure(dmi,item_handle)};
                if(!json.empty()){
                    dmi_list_.push_back(std::make_pair(json.at("object_type").as_string().c_str(),
                                                       boost::json::serialize(json)));
                }
            }
        });
    }
}

//Type 16
boost::json::object decoder::physical_memory_array(const structure &dmi)
{
    //get location
    const auto& location_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& location_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"System board or motherboard"},
                {0x04,"ISA add-on card"},
                {0x05,"EISA add-on card"},
                {0x06,"PCI add-on card"},
                {0x07,"MCA add-on card"},
                {0x08,"PCMCIA add-on card"},
                {0x09,"Proprietary add-on card"},
                {0x0A,"NuBus"},
                {0xA0,"PC-98/C20 add-on card"},
                {0xA1,"PC-98/C24 add-on card"},
                {0xA2,"PC-98/E add-on card"},
                {0xA3,"PC-98/Local bus add-on card"},
                {0xA4,"CXL add-on card"}
            };
            const auto& found {location_map.find(key)};
            if(found!=location_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get use
    const auto& array_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& array_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"System memory"},
                {0x04,"Video memory"},
                {0x05,"Flash memory"},
                {0x06,"Non-volatile RAM"},
                {0x07,"Cache memory"}
            };
            const auto& found {array_map.find(key)};
            if(found!=array_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get error correction
    const auto& correction_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& correction_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"None"},
                {0x04,"Parity"},
                {0x05,"Single-bit ECC"},
                {0x06,"Multi-bit ECC"},
                {0x07,"CRC"}
            };
            const auto& found {correction_map.find(key)};
            if(found!=correction_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const std::string& location(dmi.data_.size()>0x04 ?
                                location_get(static_cast<unsigned char>(dmi.data_.at(0x04))) :
                                std::string {});

    const std::string& use(dmi.data_.size()>0x05 ?
                                array_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                std::string {});

    const std::string& memory_error_correction(dmi.data_.size()>0x06 ?
                                correction_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                                std::string {});

    const int& maximum_capacity(dmi.data_.size()>0x0A ?
                                (static_cast<unsigned char>(dmi.data_.at(0x0A)))*0x1000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x09)))*0x10000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x08)))*0x100 +
                                static_cast<unsigned char>(dmi.data_.at(0x07)) : 0);

    const int& extended_maximum_capacity(dmi.data_.size()>0x16 ?
                                (static_cast<unsigned char>(dmi.data_.at(0x16)))*0x100000000000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x15)))*0x1000000000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x14)))*0x10000000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x13)))*0x100000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x12)))*0x1000000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x11)))*0x10000 +
                                (static_cast<unsigned char>(dmi.data_.at(0x10)))*0x100 +
                                static_cast<unsigned char>(dmi.data_.at(0x0F)) : 0);

    const int& number_of_memory_devices(dmi.data_.size()>0x0D ?
                                            static_cast<unsigned char>(dmi.data_.at(0x0D)) : 0);
    const boost::json::object& out_object{
        {"object_type", "physical_memory_array"},
        {"location", location},
        {"use", use},
        {"memory_error_correction", memory_error_correction},
        {"maximum_capacity", maximum_capacity},
        {"number_of_memory_devices", number_of_memory_devices},
        {"extended_maximum_capacity", extended_maximum_capacity}
    };
    return out_object;
}

//Type 17
boost::json::object decoder::memory_device(const structure &dmi)
{
    //get memory form-factor
    const auto& form_factor_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& factor_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"SIMM"},
                {0x04,"SIP"},
                {0x05, "Chip"},
                {0x06,"DIP"},
                {0x07,"ZIP"},
                {0x08,"Property Card"},
                {0x09,"DIMM"},
                {0x0A,"TSOP"},
                {0x0B,"Row of chips"},
                {0x0C,"RIMM"},
                {0x0D,"SODIMM"},
                {0x0E,"SRIMM"},
                {0x0F,"FB-DIMM"},
                {0x10,"Die"}
            };
            const auto& found {factor_map.find(key)};
            if(found!=factor_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get memory type
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string> type_map {
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"DRAM"},
                {0x04,"EDRAM"},
                {0x05,"VRAM"},
                {0x06,"SRAM"},
                {0x07,"RAM"},
                {0x08,"ROM"},
                {0x09,"FLASH"},
                {0x0A,"EEPROM"},
                {0x0B,"FEPROM"},
                {0x0C,"EPROM"},
                {0x0D,"CDRAM"},
                {0x0E,"3DRAM"},
                {0x0F,"SDRAM"},
                {0x10,"SGRAM"},
                {0x11,"RDRAM"},
                {0x12,"DDR"},
                {0x13,"DDR2"},
                {0x14,"DDR2 FB-DIMM"},
                {0x18,"DDR3"},
                {0x19,"FBD2"},
                {0x1A,"DDR4"},
                {0x1B,"LPDDR"},
                {0x1C,"LPDDR2"},
                {0x1D,"LPDDR3"},
                {0x1E,"LPDDR4"},
                {0x1F,"Logical non-volatile device"},
                {0x20,"HBM"},
                {0x21,"HBM2"},
                {0x22,"DDR5"},
                {0x23,"LPDDR5"},
                {0x24,"HBM3"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get memory type-detail
    const auto& type_detail_get{[](unsigned short key){
            const std::map<unsigned char,std::string> detail_map {
                {0x00,"Reserved"},
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x04,"Fast-paged"},
                {0x08,"Static colunm"},
                {0x10,"Pseudo static"},
                {0x20,"RAMBUS"},
                {0x40,"Synchronous"},
                {0x80,"CMOS"},
                {0x100,"EDO"},
                {0x200,"Window DRAM"},
                {0x400,"Cache DRAM"},
                {0x800,"Non-volatile"},
                {0x1000,"Buffered"},
                {0x2000,"Unbuffered"},
                {0x4000,"LRDIMM"}
            };
            std::vector<std::string> out;
            for(const auto& pair: detail_map){
                if((pair.first & key)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    //get memory technology
    const auto& technology_get{[](unsigned char key){
            const std::map<unsigned char,std::string> technology_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"DRAM"},
                {0x04,"NVDIMM-N"},
                {0x05,"NVDIMM-F"},
                {0x06,"NVDIMM-P"},
                {0x07,"Intel Optane"}
            };
            const auto& found {technology_map.find(key)};
            if(found!=technology_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const auto& capability_get{[](unsigned short key){
            const std::map<unsigned short,std::string>& cap_map{
                {0x01,"Reserved"},
                {0x02,"Other"},
                {0x04,"Unknown"},
                {0x08,"Volatile memory"},
                {0x10,"Byte-accessible persistent memory"},
                {0x20,"Block-accessible persistent memory"}
            };

            std::vector<std::string> out;
            for(const auto& pair: cap_map){
                if((pair.first & key)!=0){
                    out.push_back(pair.second);
                }
            }
            return out;
        }
    };

    const int& total_width {dmi.data_.size() > 0x09 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x09)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x08))) : 0};

    const int& data_width {dmi.data_.size() > 0x0B ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0B)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0A))) : 0};

    const int& size {dmi.data_.size() > 0x0D ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0D)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0C))) : 0};

    const int& size_granularity {(size & 0x8000)==0 ?
                    1024 * 1024 : 1024};

    const unsigned long long& real_size {(unsigned long long)size *
                                         (unsigned long long)size_granularity};

    const std::string& form_factor {dmi.data_.size() > 0x0E ?
                   form_factor_get(static_cast<unsigned char>(dmi.data_.at(0x0E))) :
                    std::string {}};

    const int& device_set {dmi.data_.size()>0x0F ?
                    static_cast<unsigned char>(dmi.data_.at(0x0F)) :
                    0};

    std::string device {};
    const int& device_locator {dmi.data_.size() > 0x10 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x10))-1) :
                    -1};

    if((dmi.strings_.size() > device_locator) && (device_locator >= 0)){
        device=boost::trim_copy(dmi.strings_.at(device_locator));
    }

    std::string bank {};
    const int& bank_locator {dmi.data_.size() > 0x11 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x11))-1) : -1};

    if((dmi.strings_.size() > bank_locator) && (bank_locator >= 0)){
        bank=boost::trim_copy(dmi.strings_.at(bank_locator));
    }

    const std::string& memory_type {dmi.data_.size() > 0x12 ?
                   type_get(static_cast<unsigned char>(dmi.data_.at(0x12))) :
                    std::string {}};

    const std::vector<std::string>& type_detail {dmi.data_.size() > 0x14 ?
                   type_detail_get((static_cast<unsigned char>(dmi.data_.at(0x14))) * 0x100 +
                                    static_cast<unsigned char>(dmi.data_.at(0x13))) :
                                    std::vector<std::string>{}};

    const int& speed {dmi.data_.size() > 0x16 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x16)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x15))) : 0};

    std::string manufacturer {};
    const int& manufacturer_locator {dmi.data_.size() > 0x017 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x17))-1) : -1};

    if((dmi.strings_.size() > manufacturer_locator) && (manufacturer_locator >= 0)){
        manufacturer=boost::trim_copy(dmi.strings_.at(manufacturer_locator));
    }

    std::string serial_number {};
    const int& serial_locator {dmi.data_.size() > 0x18 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x18))-1) : -1};

    if((dmi.strings_.size() > serial_locator) && (serial_locator >= 0)){
        serial_number=boost::trim_copy(dmi.strings_.at(serial_locator));
    }

    std::string asset_tag {};
    const int& asset_locator {dmi.data_.size() > 0x19 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x19))-1) : -1};

    if((dmi.strings_.size() > asset_locator) && (asset_locator >= 0)){
        asset_tag=boost::trim_copy(dmi.strings_.at(asset_locator));
    }

    std::string part_number {};
    const int& part_locator {dmi.data_.size() > 0x1A ?
                    (static_cast<unsigned char>(dmi.data_.at(0x1A))-1) : -1};

    if((dmi.strings_.size() > part_locator) && (part_locator >= 0)){
        part_number=boost::trim_copy(dmi.strings_.at(part_locator));
    }

    const int& extended_size {dmi.data_.size() > 0x1F ?
                    (static_cast<unsigned short>(dmi.data_.at(0x1F))) * 0x1000000 +
                    (static_cast<unsigned char>(dmi.data_.at(0x1E))) * 0x10000 +
                    (static_cast<unsigned char>(dmi.data_.at(0x1D))) * 0x100 +
                    (static_cast<unsigned char>(dmi.data_.at(0x1C))) : 0};

    const int& configured_speed {dmi.data_.size() > 0x21 ?
                    (static_cast<unsigned short>(dmi.data_.at(0x21))) * 0x100 +
                    static_cast<unsigned char>(dmi.data_.at(0x20)) : 0};

    const double& minimum_voltage {dmi.data_.size() > 0x23 ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x23)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x22))) / 1000.0) : 0.0};

    const double& maximum_voltage {dmi.data_.size() > 0x25 ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x25)) * 0x100 +
                      static_cast<unsigned char>(dmi.data_.at(0x24))) / 1000.0) : 0.0};

    const double& configured_voltage {dmi.data_.size() > 0x26 ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x27)) * 0x100 +
                      static_cast<unsigned char>(dmi.data_.at(0x26))) / 1000.0) : 0};

    const std::string& memory_technology {dmi.data_.size() > 0x28 ?
                    technology_get(static_cast<unsigned char>(dmi.data_.at(0x28))) :
                    std::string {}};

    const int& capability_key {dmi.data_.size()>0x2A ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x2A)) * 0x100) +
                     static_cast<unsigned char>(dmi.data_.at(0x29))) : 0};

    const std::vector<std::string>& memory_operating_mode_capability {capability_get(capability_key)};

    std::string firmware_version {};
    const int fw_version_locator {dmi.data_.size() > 0x2B ?
                    (static_cast<unsigned char>(dmi.data_.at(0x2B))-1) : -1};

    if((dmi.strings_.size() > fw_version_locator) && (fw_version_locator >= 0)){
        firmware_version=boost::trim_copy(dmi.strings_.at(fw_version_locator));
    }

    const int& module_manufacturer_id {dmi.data_.size()>0x2D ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x2D)) * 0x100) +
                      static_cast<unsigned char>(dmi.data_.at(0x2C))) : 0};

    const int& module_product_id {dmi.data_.size()>0x2F ?
                    ((static_cast<unsigned char>(dmi.data_.at(0x2F)) * 0x100) +
                      static_cast<unsigned char>(dmi.data_.at(0x2E))) : 0};

    const boost::json::object& out_object {
        {"object_type", "memory_device"},
        {"total_width", total_width},
        {"data_width", data_width},
        {"size", static_cast<long long>(real_size)},
        {"form_factor", form_factor},
        {"device_set", device_set},
        {"device", device},
        {"bank", bank},
        {"memory_type", memory_type},
        {"type_detail", boost::join(type_detail,", ")},
        {"speed", speed},
        {"manufacturer", manufacturer},
        {"serial_number", serial_number},
        {"asset_tag", asset_tag},
        {"part_number", part_number},
        {"extended_size", extended_size},
        {"configured_speed", configured_speed},
        {"minimum_voltage", minimum_voltage},
        {"maximum_voltage", maximum_voltage},
        {"configured_voltage", configured_voltage},
        {"memory_technology", memory_technology},
        {"memory_operating_mode_capability", boost::join(memory_operating_mode_capability,", ")},
        {"firmware_version", firmware_version},
        {"module_manufacturer_id", module_manufacturer_id},
        {"module_product_id", module_product_id}
    };
    return out_object;
}

//Type 18
boost::json::object decoder::memory_error_information(const structure &dmi)
{
    //get error type
    const auto& error_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"OK"},
                {0x04,"Bad read"},
                {0x05,"Parity error"},
                {0x06,"Single-bit error"},
                {0x07,"Double-bit error"},
                {0x08,"Multi-bit error"},
                {0x09,"Nibble error"},
                {0x0A,"Checksum error"},
                {0x0B,"CRC error"},
                {0x0C,"Corrected single-bit error"},
                {0x0D,"Corrected error"},
                {0x0D,"Uncorrectable error"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get error granularity
    const auto& error_granularity_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Device level"},
                {0x04,"Memory partition level"}
            };
            const auto& found {map.find(key)};
            if(found!=map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get error operation
    const auto& error_operation_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Read"},
                {0x04,"Write"},
                {0x05,"Partial write"}
            };
            const auto& found {map.find(key)};
            if(found!=map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const std::string& error_type {dmi.data_.size()>0x04 ?
                    error_type_get(static_cast<unsigned char>(dmi.data_.at(0x04))) :
                    std::string {}};

    const std::string& error_granularity {dmi.data_.size()>0x05 ?
                    error_granularity_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const std::string& error_operation {dmi.data_.size()>0x06 ?
                   error_operation_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                    std::string {}};

    const boost::json::object& out_object{
        {"object_type", "memory_error_information"},
        {"error_type", error_type},
        {"error_granularity", error_granularity},
        {"error_operation", error_operation}
    };
    return out_object;
}

//Type 21
boost::json::object decoder::builtin_pointing_device(const structure &dmi)
{
    //get type
    const auto& device_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Mouse"},
                {0x04,"Track Ball"},
                {0x05,"Track Point"},
                {0x06,"Glide Point"},
                {0x07,"Touch Pad"},
                {0x08,"Touch Screen"},
                {0x09,"Optical Sensor"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get interface
    const auto& interface_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& interface_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Serial"},
                {0x04,"PS/2"},
                {0x05,"Infrared"},
                {0x06,"HP-HIL"},
                {0x07,"Bus mouse"},
                {0x08,"ADB (Apple Desktop Bus)"},
                {0xA0,"Bus mouse DB-9"},
                {0xA1,"Bus mouse micro-DIN"},
                {0xA2,"USB"},
                {0xA3,"I2C"},
                {0xA4,"SPI"}
            };
            const auto& found {interface_map.find(key)};
            if(found!=interface_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const std::string& device_type {dmi.data_.size()>0x04 ?
                            device_type_get(static_cast<unsigned char>(dmi.data_.at(0x04))) :
                            std::string {}};

    const std::string& interface {dmi.data_.size()>0x05 ?
                            interface_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                            std::string {}};

    const int& number_of_buttons(dmi.data_.size()>0x06 ?
                                 static_cast<unsigned char>(dmi.data_.at(0x06)) : 0);

    const boost::json::object& out_object{
        {"object_type", "builtin_pointing_device"},
        {"device_type", device_type},
        {"interface", interface},
        {"number_of_buttons", number_of_buttons}
    };
    return out_object;
}

//Type 22
boost::json::object decoder::portable_battery(const structure &dmi)
{
    //get battery chemistry
    const auto& chemistry_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& chemistry_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Lead Acid"},
                {0x04,"Nickel Cadmium"},
                {0x05,"Nickel metal hydride"},
                {0x06,"Lithium-ion"},
                {0x07,"Zinc air"},
                {0x08,"Lithium Polymer"}
            };
            const auto& found {chemistry_map.find(key)};
            if(found!=chemistry_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

   const int& location_locator (dmi.data_.size()>0x04 ?
                                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);
   std::string location {};
   if((dmi.strings_.size()>location_locator) && (location_locator>=0)){
       location=boost::trim_copy(dmi.strings_.at(location_locator));
   }

   const int& manufacturer_locator (dmi.data_.size()>0x05 ?
                                    static_cast<unsigned char>(dmi.data_.at(0x05))-1 : -1);
   std::string manufacturer {};
   if((dmi.strings_.size()>manufacturer_locator) && (manufacturer_locator>=0)){
       manufacturer=boost::trim_copy(dmi.strings_.at(manufacturer_locator));
   }

   const int& date_locator (dmi.data_.size()>0x06 ?
                                    static_cast<unsigned char>(dmi.data_.at(0x06))-1 : -1);
   std::string manufacture_date {};
   if((dmi.strings_.size()>date_locator) && (date_locator>=0)){
       manufacture_date=boost::trim_copy(dmi.strings_.at(date_locator));
   }

   const int& serial_locator (dmi.data_.size()>0x07 ?
                                    static_cast<unsigned char>(dmi.data_.at(0x07))-1 : -1);
   std::string serial_number {};
   if((dmi.strings_.size()>serial_locator) && (serial_locator>=0)){
       serial_number=boost::trim_copy(dmi.strings_.at(serial_locator));
   }

   const int& name_locator (dmi.data_.size()>0x08 ?
                            static_cast<unsigned char>(dmi.data_.at(0x08))-1 : -1);
   std::string device_name {};
   if((dmi.strings_.size()>name_locator) && (name_locator>=0)){
       device_name=boost::trim_copy(dmi.strings_.at(name_locator));
   }

   const std::string& device_chemistry {dmi.data_.size()>0x09 ?
                                        chemistry_get(static_cast<unsigned char>(dmi.data_.at(0x09))) :
                                            std::string {}};

   const int sdbs_chemistry_locator (dmi.data_.size()>0x14 ?
                                     static_cast<unsigned char>(dmi.data_.at(0x14))-1 : -1);
   const std::string& sdbs_device_chemistry {dmi.strings_.size()>sdbs_chemistry_locator && sdbs_chemistry_locator>=0 ?
                                      boost::trim_copy(dmi.strings_.at(sdbs_chemistry_locator)) :
                                      std::string {}};

   const boost::json::object& out_object{
       {"object_type", "portable_battery"},
       {"location", location},
       {"manufacturer", manufacturer},
       {"manufacture_date", manufacture_date},
       {"serial_number", serial_number},
       {"device_name", device_name},
       {"device_chemistry", device_chemistry},
       {"sdbs_device_chemistry", sdbs_device_chemistry}
   };
   return out_object;
}

//Type 26
boost::json::object decoder::voltage_probe(const structure &dmi)
{
    //get voltage probe status
    const auto& status_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& status_map {
                {0x20,"Other"},
                {0x40,"Unknown"},
                {0x60,"Ok"},
                {0x80,"Non-critical"},
                {0xA0,"Critical"},
                {0xC0,"Non-recoverable"}
            };
            for(const auto& pair: status_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    //get voltage probe location
    const auto& location_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& location_map {
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Processor"},
                {0x04,"Disk"},
                {0x05,"Peripheral Bay"},
                {0x06,"System Management Module"},
                {0x07,"Motherboard"},
                {0x08,"Memory Module"},
                {0x09,"Processor Module"},
                {0x0A,"Power Unit"},
                {0x0B,"Add-in Card"}
            };
            for(const auto& pair: location_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    const int& description_locator {dmi.data_.size()>0x04 ?
                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 :
                    -1};

    const std::string& description {description_locator>=0 && dmi.strings_.size()>description_locator ?
                    boost::trim_copy(dmi.strings_.at(description_locator)) :
                    std::string {}};

    const std::string& location {dmi.data_.size()>0x05 ?
                    location_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const std::string& status {dmi.data_.size()>0x05 ?
                    status_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const int& maximum_value {dmi.data_.size()>0x07 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x07)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x06))) : 0};

    const int& minimum_value {dmi.data_.size()>0x09 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x09)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x08))) : 0};

    const int& resolution {dmi.data_.size()>0x0B ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0B)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0A))) : 0};

    const int& tolerance {dmi.data_.size()>0x0D ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0D)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0C))) : 0};

    const int& accuracy {dmi.data_.size()>0x0F ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0F)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0E))) : 0};

    const int& nominal_value {dmi.data_.size()>0x15 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x15)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x14))) : 0};


    const boost::json::object& out_object {
        {"object_type", "voltage_probe"},
        {"description", description},
        {"location", location},
        {"status", status},
        {"maximum_value", maximum_value==0x8000 ? 0 : maximum_value/1000.0},
        {"minimum_value", minimum_value==0x8000 ? 0 : minimum_value/1000.0},
        {"resolution", resolution==0x8000 ? 0 : resolution/1000.0},
        {"tolerance", tolerance==0x8000 ? 0 : tolerance/1000.0},
        {"accuracy", accuracy==0x8000 ? 0 : accuracy/1000.0},
        {"nominal_value", nominal_value==0x8000 ? 0 : nominal_value/1000.0}
    };
    return out_object;
}

//Type 27
boost::json::object decoder::cooling_device(const structure &dmi)
{
    //get device type
    const auto& device_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map {
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Fan"},
                {0x04,"Centrifugal Blower"},
                {0x05,"Chip Fan"},
                {0x06,"Cabinet Fan"},
                {0x07,"Power Supply Fan"},
                {0x08,"Heat Pipe"},
                {0x09,"Integrated Refrigeration"},
                {0x10,"Active Cooling"},
                {0x11,"Passive Cooling"}
            };

            for(const auto& pair: type_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    //get device status
    const auto& device_status_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& status_map {
                {0x20,"Other"},
                {0x40,"Unknown"},
                {0x60,"OK"},
                {0x80,"Non-critical"},
                {0xA0,"Critical"},
                {0xC0,"Non-recoverable"}
            };

            for(const auto& pair: status_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    const int& temperature_probe_handle {dmi.data_.size()>0x05 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x05)) * 0100 +
                     static_cast<unsigned char>(dmi.data_.at(0x04))) :
                    0};

    const std::string& device_type {dmi.data_.size()>0x06 ?
                    device_type_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                    std::string {}};

    const std::string& device_status {dmi.data_.size()>0x06 ?
                    device_status_get(static_cast<unsigned char>(dmi.data_.at(0x06))) :
                    std::string {}};

    const int& cooling_unit_group {dmi.data_.size()>0x07 ?
                    static_cast<unsigned char>(dmi.data_.at(0x07)) :
                    0};

    const int& nominal_speed {dmi.data_.size()>0x0D ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0D)) * 0100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0C))) :
                     0};

    const int& description_locator {dmi.data_.size()>0x0E ?
                    static_cast<unsigned char>(dmi.data_.at(0x0E))-1 :
                    -1};

    const std::string& description {description_locator>=0 && dmi.strings_.size()>description_locator ?
                    boost::trim_copy(dmi.strings_.at(description_locator)) :
                    std::string {}};

    const boost::json::object& out_object {
        {"object_type", "cooling_device"},
        {"temperature_probe_handle", temperature_probe_handle},
        {"device_type", device_type},
        {"device_status", device_status},
        {"cooling_unit_group", cooling_unit_group},
        {"nominal_speed", nominal_speed==0x8000 ? 0 : nominal_speed},
        {"description", description}
    };
    return out_object;
}

//Type 28
boost::json::object decoder::temperature_probe(const structure &dmi)
{
    //get temperature probe status
    const auto& status_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& status_map {
                {0x20,"Other"},
                {0x40,"Unknown"},
                {0x60,"Ok"},
                {0x80,"Non-critical"},
                {0xA0,"Critical"},
                {0xC0,"Non-recoverable"}
            };
            for(const auto& pair: status_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    //get temparature probe location
    const auto& location_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& location_map {
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Processor"},
                {0x04,"Disk"},
                {0x05,"Peripheral Bay"},
                {0x06,"System Management Module"},
                {0x07,"Motherboard"},
                {0x08,"Memory Module"},
                {0x09,"Processor Module"},
                {0x0A,"Power Unit"},
                {0x0B,"Add-in Card"},
                {0x0C,"Front Panel Board"},
                {0x0D,"Back Panel Board"},
                {0x0E,"Power System Board"},
                {0x0F,"Drive Back Plane"}
            };
            for(const auto& pair: location_map){
                if((pair.first & key)!=0){
                    return pair.second;
                }
            }
            return std::string {};
        }
    };

    const int& description_locator {dmi.data_.size()>0x04 ?
                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 :
                    -1};

    const std::string& description {description_locator>=0 && dmi.strings_.size()>description_locator ?
                    boost::trim_copy(dmi.strings_.at(description_locator)) :
                    std::string {}};

    const std::string& location {dmi.data_.size()>0x05 ?
                    location_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const std::string& status {dmi.data_.size()>0x05 ?
                    status_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const int& maximum_value {dmi.data_.size()>0x07 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x07)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x06))) : 0};

    const int& minimum_value {dmi.data_.size()>0x09 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x09)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x08))) : 0};

    const int& resolution {dmi.data_.size()>0x0B ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0B)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0A))) : 0};

    const int& tolerance {dmi.data_.size()>0x0D ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0D)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0C))) : 0};

    const int& accuracy {dmi.data_.size()>0x0F ?
                    (static_cast<unsigned char>(dmi.data_.at(0x0F)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x0E))) : 0};

    const int& nominal_value {dmi.data_.size()>0x15 ?
                    (static_cast<unsigned char>(dmi.data_.at(0x15)) * 0x100 +
                     static_cast<unsigned char>(dmi.data_.at(0x14))) : 0};

    const boost::json::object& out_object {
        {"object_type", "temperature_probe"},
        {"description", description},
        {"location", location},
        {"status", status},
        {"maximum_value", maximum_value==0x8000 ? 0 : maximum_value/1000.0},
        {"minimum_value", minimum_value==0x8000 ? 0 : minimum_value/1000.0},
        {"resolution", resolution==0x8000 ? 0 : resolution/1000.0},
        {"tolerance", tolerance==0x8000 ? 0 : tolerance/1000.0},
        {"accuracy", accuracy==0x8000 ? 0 : accuracy/1000.0},
        {"nominal_value", nominal_value==0x8000 ? 0 : nominal_value/1000.0}
    };
    return out_object;
}

//Type 29
boost::json::object decoder::electrical_current_probe(const structure &dmi)
{
    const boost::json::object& out_object {
        {"object_type","electrical_current_probe"}
    };
    return out_object;
}

//Type 34
boost::json::object decoder::management_device_information(const structure &dmi)
{
    //get device type
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string> type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"National Semiconductor LM75"},
                {0x04,"National Semiconductor LM78"},
                {0x05,"National Semiconductor LM79"},
                {0x06,"National Semiconductor LM80"},
                {0x07,"National Semiconductor LM81"},
                {0x08,"Analog Devices ADM9240"},
                {0x09,"Dallas Semiconductor DS1780"},
                {0x0A,"Maxim 1617"},
                {0x0B,"Genesys GL518SM"},
                {0x0C,"Winbond W83781D"},
                {0x0D,"Holtek HT82H791"}
            };
            const auto& found {type_map.find(key)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get address type
    const auto& address_type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& address_type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"I/O Port"},
                {0x04,"Memory"},
                {0x05,"SM Bus"}
            };
            const auto& found {address_type_map.find(key)};
            if(found!=address_type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    const int& description_locator (dmi.data_.size()>0x04 ?
                                    static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);

    const std::string& description {(description_locator>=0) && (dmi.strings_.size()>description_locator) ?
                boost::trim_copy(dmi.strings_.at(description_locator)) :
                    std::string {}};

    const std::string& type {dmi.data_.size()>0x05 ?
                    type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                    std::string {}};

    const int& address {dmi.data_.size() > 0x09 ?
                     (static_cast<unsigned short>(dmi.data_.at(0x09))) * 0x1000000 +
                     (static_cast<unsigned char>(dmi.data_.at(0x08))) * 0x10000 +
                     (static_cast<unsigned char>(dmi.data_.at(0x07))) * 0x100 +
                     (static_cast<unsigned char>(dmi.data_.at(0x06))) : 0};

    const std::string& address_type {dmi.data_.size()>0x0A ?
                    address_type_get(static_cast<unsigned char>(dmi.data_.at(0x0A))) :
                    std::string {}};

    const boost::json::object& out_object{
        {"object_type", "management_device_information"},
        {"description", description},
        {"type", type},
        {"address", address},
        {"address_type", address_type}
    };
    return out_object;
}

//Type 41
boost::json::object decoder::onboard_device_extended_information(const structure &dmi)
{
    const auto& type_get{[](unsigned char key){
            const std::map<unsigned char,std::string>& type_map{
                {0x01,"Other"},
                {0x02,"Unknown"},
                {0x03,"Video"},
                {0x04,"SCSI Controller"},
                {0x05,"Ethernet"},
                {0x06,"Token Ring"},
                {0x07,"Sound"},
                {0x08,"PATA Controller"},
                {0x09,"SATA Controller"},
                {0x0A,"SAS Controller"},
                {0x0B,"Wireless LAN"},
                {0x0C,"Bluetooth"},
                {0x0D,"WWAN"},
                {0x0E," eMMC (embedded Multi-Media Controller)"},
                {0x0F,"NVMe Controller"},
                {0x10,"UFS Controller"}
            };
            const auto& found {type_map.find(key & 0x3F)};
            if(found!=type_map.end()){
                return found->second;
            }
            return std::string {};
        }
    };

    //get device status
    const auto& status_get{[](unsigned char key){
            return ((key & 0x80)>0 ? std::string {"Enabled"} :
                                     std::string {"Disabled"});
        }
    };

    const int& reference_locator(dmi.data_.size()>0x04 ?
                                     static_cast<unsigned char>(dmi.data_.at(0x04))-1 : -1);

    const std::string& reference_designation {(reference_locator>=0) && (dmi.strings_.size()>reference_locator) ?
                                              boost::trim_copy(dmi.strings_.at(reference_locator)) :
                                              std::string {}};

    const std::string& device_type {dmi.data_.size()>0x05 ?
                                    type_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                    std::string {}};

    const std::string& device_status {dmi.data_.size()>0x05 ?
                                       status_get(static_cast<unsigned char>(dmi.data_.at(0x05))) :
                                       std::string {}};

    const boost::json::object& out_object {
        {"object_type", "onboard_device_extended_information"},
        {"reference_designation", reference_designation},
        {"device_type", device_type},
        {"device_status", device_status}
    };
    return out_object;
}

//Type 44
boost::json::object decoder::processor_additional_information(const structure &dmi)
{
    const boost::json::object& out_object {
        {"object_type", "processor_additional_information"}
    };
    return out_object;
}

