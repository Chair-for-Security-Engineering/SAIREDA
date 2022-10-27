#include "Util/SortingNetwork.h"

using namespace secutil;

SortingNetwork::SortingNetwork(unsigned number_inputs){
    num_inputs = number_inputs;
    network = std::vector<std::pair<unsigned,unsigned>>();
}

SortingNetwork::SortingNetwork(std::string filename){

    std::ifstream inputFile(filename);
    std::string line;
    std::string compare;
    unsigned first, second;

    if(getline(inputFile, line)){
        num_inputs = std::atoi(line.c_str());
    }
    while(getline(inputFile, line)){
        size_t pos_start ;
        //Get the individual compare operations
        while((pos_start = line.find("(")) != std::string::npos){
            size_t pos_end = line.find(")");
            compare = line.substr(pos_start+1, pos_end-pos_start-1);
            //Get the two wire indices that are compared
            size_t pos_delimiter = compare.find(",");
            first = std::atoi(compare.substr(0, pos_delimiter).c_str());
            second = std::atoi(compare.substr(pos_delimiter+1).c_str());
            //Ensure that first entry is smaller than second entry
            if(second < first){
                unsigned temp = second;
                second = first;
                first = temp;
            }
            //Add the comparison to the sorting network
            network.push_back(std::pair<unsigned,unsigned>(first, second));
            //Erase the current comparator from the line
            line.erase(pos_start, pos_end-pos_start+1);
        }
    }
    inputFile.close();
}

void SortingNetwork::addComparison(unsigned first, unsigned second){
    network.push_back(std::pair<unsigned,unsigned>(first, second));
}

unsigned SortingNetwork::getNumberOfInputs(){
    return num_inputs;
}

std::vector<std::pair<unsigned,unsigned>> SortingNetwork::getNetwork(){
    return network;
}