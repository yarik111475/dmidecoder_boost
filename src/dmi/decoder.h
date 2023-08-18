#ifndef DECODER_H
#define DECODER_H

#include <vector>
#include <string>
#include "entry.h"
#include "structure.h"
#include <boost/json.hpp>
#include <boost/property_tree/ptree.hpp>

class decoder
{
private:
    std::string error_str_ {};
    //const std::string entry_path_ {"/home/yaroslav/dmi_tables/centos/smbios_entry_point"};
    //const std::string table_path_ {"/home/yaroslav/dmi_tables/centos/DMI"};

    //const std::string entry_path_ {"C:\\tables\\smbios_entry_point"};
    //const std::string table_path_ {"C:\\tables\\DMI"};


    const std::string entry_path_ {"/sys/firmware/dmi/tables/smbios_entry_point"};
    const std::string table_path_ {"/sys/firmware/dmi/tables/DMI"};
    std::vector<std::string> anchors_ {};
    bool checksum(const std::vector<char> &data);

    entry t_point_;
    structure t_structure_;
    std::vector<structure> structure_list_ {};
    std::vector<std::pair<std::string,std::string>> dmi_list_{};

    bool decode_entry();
    std::vector<structure> decode_table();
    boost::json::object decode_structure(const structure& dmi, int type);

public:
    explicit decoder(){
        //fill predefined anchors
        anchors_.push_back("_SM_");
        anchors_.push_back("_SM3_");
    };
    ~decoder()=default;
    inline std::string error()const{
        return error_str_;
    } 
    std::vector<std::pair<std::string,std::string>> decode_information();

private:
    //Type 0
    boost::json::object bios_information(const structure& dmi);

    //Type 1
    boost::json::object system_information(const structure& dmi);

    //Type 2
    boost::json::object baseboard_information(const structure& dmi);

    //Type 3
    boost::json::object chassis_information(const structure& dmi);

    //Type 4
    boost::json::object processor_information(const structure& dmi);

    //Type 5, Obsolete
    boost::json::object memory_controller_information(const structure& dmi);

    //Type 6, Obsolete
    boost::json::object memory_module_information(const structure& dmi);

    //Type 7
    boost::json::object cache_information(const structure& dmi);

    //Type 8
    boost::json::object port_connector_information(const structure& dmi);

    //Type 9
    boost::json::object system_slot_information(const structure& dmi);

    //Type 10
    boost::json::object onboard_device_information(const structure& dmi);

    //Type 11
    boost::json::object oem_strings(const structure& dmi);

    //Type 12
    boost::json::object system_configuration_options(const structure& dmi);

    //Type 13
    boost::json::object bios_language_information(const structure& dmi);

    //for decode additional structures with associations
    void group_associations(const structure& dmi);

    //Type 16
    boost::json::object physical_memory_array(const structure& dmi);

    //Type 17
    boost::json::object memory_device(const structure& dmi);

    //Type 18
    boost::json::object memory_error_information(const structure& dmi);

    //Type 21
    boost::json::object builtin_pointing_device(const structure& dmi);

    //Type 22
    boost::json::object portable_battery(const structure& dmi);

    //Type 26
    boost::json::object voltage_probe(const structure& dmi);

    //Type 27
    boost::json::object cooling_device(const structure& dmi);

    //Type 28
    boost::json::object temperature_probe(const structure& dmi);

    //Type 29
    boost::json::object electrical_current_probe(const structure& dmi);

    //Type 34
    boost::json::object management_device_information(const structure& dmi);

    //Type 41, Obsolete
    boost::json::object onboard_device_extended_information(const structure& dmi);

    //Type 44
    boost::json::object processor_additional_information(const structure& dmi);
};

#endif // DECODER_H
