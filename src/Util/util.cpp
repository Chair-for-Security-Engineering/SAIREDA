#include "Util/util.h"

///Helperfunction that splits strings at a given delimiter char
std::vector<std::string> secutil::split(const std::string& s, const char *delimiter){
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, *delimiter)){
        tokens.push_back(token);
    }
    return tokens;
}

bool secutil::vectorContainsValue(
            std::vector<mlir::Value> vector, 
            mlir::Value search
){
    for(mlir::Value val : vector){
        if(val == search)
            return true;
    }
    return false;
}

bool secutil::vectorContainsOperation(
            std::vector<mlir::Operation*> vector, 
            mlir::Operation *search
){
    for(mlir::Operation* op : vector){
        if(op == NULL) continue;
        //Check for same name
        if(op->getName() == search->getName()){
            //Check for same result
            if(op->getResult(0) == search->getResult(0)){
                //Check for same openands
                for(unsigned i=0; i<op->getOperands().size(); i++){
                    if(op->getOperand(i) == search->getOperand(i))
                        return true;
                }
            }
        }
    }
    return false;
}