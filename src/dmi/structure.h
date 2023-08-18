#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <string>
#include <vector>

struct structure
{
    //type
    int type_ {};
    //length of data block (exclude strings block)
    int length_ {};
    //handle
    int handle_ {};
    //data block
    std::vector<char> data_ {};
    //strings block
    std::vector<std::string> strings_ {};

    explicit structure()=default;
    explicit structure(int type, int length,int handle,const std::vector<char>& data,const std::vector<std::string>& strings)
        :type_{type},length_{length},handle_{handle},data_{data},strings_{strings}{
    }
};

#endif // STRUCTURE_H
