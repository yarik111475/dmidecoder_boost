#include <vector>
#include <sstream>
#include <iostream>
#include <QJsonDocument>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "dmi/decoder.h"
#include "dmi/structure.h"

int main(int argc,char* argv[]){
    decoder dmi_decoder{};
    try{
        const std::vector<std::pair<std::string,std::string>>& dmi_list {dmi_decoder.decode_information()};
        if(!dmi_list.empty()){
            for(const std::pair<std::string,std::string>& dmi: dmi_list){
                if(!dmi.second.empty()){
                    QJsonDocument doc=QJsonDocument::fromJson(QString::fromStdString(dmi.second).toUtf8());
                    std::cout<<doc.toJson().toStdString();

                    //std::stringstream in_ss;
                    //in_ss<<dmi_str;
                    //boost::property_tree::ptree ptree_;
                    //boost::property_tree::json_parser::read_json(in_ss,ptree_);

                    //std::stringstream out__ss;
                    //boost::property_tree::json_parser::write_json(out__ss,ptree_);
                    //std::cout<<out__ss.str()<<std::endl;
                }
            }
        }
        else{
            if(!dmi_decoder.error().empty()){
                std::cerr<<dmi_decoder.error()<<std::endl;
                std::getchar();
                return EXIT_FAILURE;
            }
        }
    }catch(const std::exception& ex){
        std::cout<<"error: "<<ex.what()<<std::endl;
    }

    std::getchar();
    return EXIT_SUCCESS;
}
