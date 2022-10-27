/*
 * -----------------------------------------------------------------
 * COMPANY : Ruhr-University Bochum, Chair for Security Engineering
 * AUTHOR  : Jakob Feldtkeller (jakob.feldtkeller@rub.de)
 * -----------------------------------------------------------------
 *
 * Copyright (c) 2022, Jakob Feldtkeller
 *
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Please see license.rtf and README for license and further instructions.
 */
#include "Passes/GadgetInsertion.h"

namespace circt{
namespace secfir{

using namespace circt;

    /// Function that creates a shared implementation of a given module. 
    secfir::ModuleOp secfir::InsertGadgetsLogicPass::maskAndDuplicateModule(
            secfir::ModuleOp &module, 
            std::vector<mlir::Attribute> toShare
    ){
        //Get builder for IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Define duplication and share parameter
        unsigned numberShares = parameterOrder+1;
        unsigned numberDuplications = 2*parameterActiveOrder+1;
        
        //Get input and output signals of original module
        secfir::SmallVector<secfir::ModulePortInfo, 4> oldPorts;
        module.getPortInfo(oldPorts);

        //Count number of ports that should be shared.
        //Number of 1's (ASCII) in encoding
        unsigned numberOfSharedPorts = 0;
        for(unsigned i=0; i<oldPorts.size(); i++){
            if(toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                numberOfSharedPorts++;
                //Mark users of shared inputs for sharing
                for(mlir::Operation* inst : module.getArguments()[i].getUsers()){
                    auto shareIt = builder.getBoolAttr(true);
                    inst->setAttr("ToShare", shareIt);
                }
            }
        }
        //Create a new list for input and output ports, where the defined port can 
        //be shared
        secfir::SmallVector<secfir::ModulePortInfo, 8> newPorts;
        newPorts.reserve(oldPorts.size()+numberOfSharedPorts*(numberShares-1));
        //Share and duplicate all input ports
        shareAndDuplicateInputPorts(
                &getContext(), 
                &oldPorts, 
                toShare, 
                numberShares, 
                numberDuplications, 
                &newPorts);
        
        //Get number of required randomness
        unsigned startIndexFreshRandomness;
        unsigned numberRand;
        if(module.getAttrOfType<mlir::IntegerAttr>("RequiredRandomness")){
            numberRand = module.getAttrOfType<mlir::IntegerAttr>("RequiredRandomness").getInt();
        }else{
            numberRand = 0;
        }
        //Add input ports for the required randomness
        addRandomnessPorts(
                &getContext(), 
                numberRand, 
                &startIndexFreshRandomness, 
                &newPorts);
        //Share and duplicate output ports
        secfir::SmallVector<secfir::ModulePortInfo, 4> outPorts;
        module.getOutputPortInfo(outPorts);
        shareAndDuplicateOutputPorts(
                &getContext(), 
                &outPorts, 
                numberShares, 
                numberDuplications, 
                &newPorts);

        //Create a new module with the shared and duplicated port list
        builder.setInsertionPoint(module);
        auto nameAttr = builder.getStringAttr(module.getName());
        secfir::ModuleOp sharedModule = builder.create<secfir::ModuleOp>(
            module.getLoc(), nameAttr, newPorts);


        //Create a map between the SSA values of the old module and those of the new 
        //module
        mlir::Value clk;
        unsigned mapSize = module.getBodyBlock()->getOperations().size();
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> valueMap(mapSize);
        unsigned j = 0; //Index for the new module list
        //Go though the list of input ports of the old module
        for(unsigned i=0; i<oldPorts.size(); i++){
            if(!toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                //Add a duplicated values to the mapping, if the port is not shared
                std::vector<mlir::Value> duplicatedValue(numberDuplications);
                for(unsigned dup=0; dup<numberDuplications; dup++){
                    duplicatedValue[dup] = sharedModule.getArguments()[j];
                    j++;
                }   
                std::vector<std::vector<mlir::Value>> singleValueVector;
                singleValueVector.push_back(duplicatedValue);
                valueMap[module.getArguments()[i]] = singleValueVector;

                mlir::Value val = module.getArguments()[i];
                //Find clock of the module
                if(val.getType().isa<secfir::ClockType>()){
                    clk = module.getArguments()[i];
                }
            }else{ //Encoding bit is 1 (ASCII)
                //Add the different shares to the mapping for shared ports
                std::vector<std::vector<mlir::Value>> sharedAndDuplicatedValue(numberShares);
                for(unsigned s=0; s<numberShares; s++){
                    std::vector<mlir::Value> duplicatedValue(numberDuplications);
                    for(unsigned dup=0; dup<numberDuplications; dup++){
                        duplicatedValue[dup] = sharedModule.getArguments()[j];
                        j++;
                    }
                    sharedAndDuplicatedValue[s] = duplicatedValue;
                } 
                valueMap[module.getArguments()[i]] = sharedAndDuplicatedValue;
            }
        }

        // Create a list for operations that should be erased at the end
        mlir::OpBuilder opBuilder(sharedModule.body());
        std::vector<mlir::Operation*> deleteOperations;
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> dummyMap;
        //Mark current terminator operation for deletion (will be replaced
        //by new one)
        for(auto &searchOp : sharedModule.getBodyBlock()->getOperations()){
            if(secfir::dyn_cast<secfir::OutputOp>(searchOp)){
                deleteOperations.push_back(&searchOp);
            }
        }
  
        //Walk though module body and creat shared operation if necessary
        unsigned operationId = 0;
        for (auto &op : module.getBodyBlock()->getOperations()) {
            shareAndDuplicateOperation(
                op,
                opBuilder,
                sharedModule,
                clk,
                valueMap,
                dummyMap,
                numberShares,
                numberDuplications,
                startIndexFreshRandomness,
                operationId,
                parameterAsModule,
                parameterPipelineGadgets);
            operationId++;
        }
        //Erase all operation that were replaced by gadgets
        for(unsigned i=0; i<deleteOperations.size(); i++){
            deleteOperations[i]->erase();
        } 
        return sharedModule;
    }

    /// Function that given a list of input ports shares and duplicates those
    /// ports. Only marked ports are shared, while all ports are duplicated.
    /// Does not handle case of flipped data types.
    ///
    /// context                     The current context
    /// ports                       List of input ports that should be shared and duplicated
    /// toShare                     List of attributes that indicate which inputs to share
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create
    /// sharedAndDuplicatedPorts    Resulting list of shared and duplicated ports
    void shareAndDuplicateInputPorts(
        mlir::MLIRContext *context,
        secfir::SmallVector<secfir::ModulePortInfo, 4> *ports,
        std::vector<mlir::Attribute> toShare,
        unsigned numberShares,
        unsigned numberDuplications,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts  
    ){
        //Get a builder to create attributes
        mlir::OpBuilder builder(context);
        //Go though all ports and create the defined number of shares if necessary
        for(unsigned i=0; i<ports->size(); i++){
            auto &port = (*ports)[i];
            //Check whether current port should be shared 
            //(encoding bit set to 1 (ASCII))
            if(toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                //Get width of the port
                int32_t width = port.type.getBitWidthOrSentinel();
                //Create required shares for more than one share
                if(numberShares > 1){
                    for(unsigned share=0; share<numberShares; share++){
                        //Create required duplication for more than one duplication 
                        if(numberDuplications > 1){
                            for(unsigned duplicate=0; duplicate<numberDuplications; duplicate++){
                                //Create a name for the share and duplication
                                auto nameShare = builder.getStringAttr(
                                    port.name.getValue().str() + "_s" + 
                                    std::to_string(share) + "_d" + std::to_string(duplicate));
                                //Create port entry with duplicated share type
                                sharedAndDuplicatedPorts->push_back({
                                        nameShare, 
                                        secfir::DuplicatedShareType::get(
                                                context, width, share, duplicate)});     
                            } 
                        }else{ //When only one instance is required have another nameing
                            //Create a name for the share
                            auto nameShare = builder.getStringAttr(
                                    port.name.getValue().str() + "_s" + 
                                    std::to_string(share));
                            //Create port entry with duplicated share type zero
                            sharedAndDuplicatedPorts->push_back({
                                    nameShare, 
                                    secfir::DuplicatedShareType::get(context, width, share, 0)});
                        }
                    }   
                }else{
                    //Omit share index when there is no shareing
                    for(unsigned duplicate=0; duplicate<numberDuplications; duplicate++){
                        //Create a name for the share
                        auto nameShare = builder.getStringAttr(
                            port.name.getValue().str() + "_d" + std::to_string(duplicate));
                        //Create port entry with duplicated share type
                        sharedAndDuplicatedPorts->push_back({
                                nameShare, 
                                secfir::DuplicatedShareType::get(
                                        context, width, 0, duplicate)});     
                    } 
                }                
            }else{
                //If port is not shared than only duplicate the port
                for(unsigned duplicate=0; duplicate<numberDuplications; duplicate++){
                    //Create a name for the share
                    auto dupName = builder.getStringAttr(
                        port.name.getValue().str() + "_" + std::to_string(duplicate));
                    //Keep type if it is a clock or reset, and create a share and duplicate
                    //type otherwise
                    if(port.type.isa<secfir::ClockType>() ||
                            port.type.isa<secfir::ResetType>()){
                        sharedAndDuplicatedPorts->push_back({dupName, port.type});
                    }else{
                        int32_t width = port.type.getBitWidthOrSentinel();
                        sharedAndDuplicatedPorts->push_back({dupName, 
                                secfir::DuplicatedShareType::get(
                                    context, width, 0, duplicate)});
                    }                    
                }
            }
        }
    }


    /// Function shares and duplicates a given list of output ports.
    /// Currently all ports are shared and duplicated. This function
    /// can only handle ports with flipped types.
    ///
    /// context                     Current context
    /// ports                       List of output ports to share and duplicate
    /// numberShares                Number of shares to create
    /// numberDuplications          Number of duplications to create
    /// sharedAndDuplicatedPorts    Resulting list of shared and duplicated ports
    void shareAndDuplicateOutputPorts(
        mlir::MLIRContext *context,
        secfir::SmallVector<secfir::ModulePortInfo, 4> *ports,
        unsigned numberShares,
        unsigned numberDuplications,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts
    ){
        //Get a builder for attribute creation
        mlir::OpBuilder builder(context);
        //Go through all output ports and share and duplicate them
        for(unsigned i=0; i<ports->size(); i++){
            auto &port = (*ports)[i];
            //Get width of output port
            secfir::FlipType fType = port.type.dyn_cast<secfir::FlipType>();
            int32_t width = fType.getElementType().getBitWidthOrSentinel();
            //Create a new port for every share and duplication
            if(numberShares > 1){
                //Create all shares if more than one share is required
                for(unsigned share=0; share<numberShares; share++){
                    if(numberDuplications > 1){
                        //Create all duplications if more than one instance is required
                        for(unsigned duplicate=0; duplicate<numberDuplications; duplicate++){
                            //Create a name for the share
                            auto nameShare = builder.getStringAttr(
                                port.name.getValue().str() + "_s" + 
                                std::to_string(share) + "_d" + std::to_string(duplicate));
                            //Create the output port
                            sharedAndDuplicatedPorts->push_back({
                                nameShare, 
                                secfir::FlipType::get(
                                    secfir::DuplicatedShareType::get(
                                        context, width, share, duplicate))});
                        }
                    //Give a different name if no duplication is required
                    }else{
                        auto nameShare = builder.getStringAttr(
                                port.name.getValue().str() + "_s" + 
                                std::to_string(share));
                        sharedAndDuplicatedPorts->push_back({
                                nameShare, 
                                secfir::FlipType::get(
                                    secfir::DuplicatedShareType::get(
                                        context, width, share, 0))});
                    }
                }
            }else{
                //Omit share index when there is no shareing
                for(unsigned duplicate=0; duplicate<numberDuplications; duplicate++){
                    //Create a name for the share
                    auto nameShare = builder.getStringAttr(
                        port.name.getValue().str() + "_d" + std::to_string(duplicate));
                    //Create port entry with duplicated share type
                    sharedAndDuplicatedPorts->push_back({
                            nameShare, 
                            secfir::FlipType::get(
                                    secfir::DuplicatedShareType::get(
                                            context, width, 0, duplicate))});     
                } 
            }    
        }
    }

    /// Function that adds a specified number of input ports for randomness
    /// to a given list of ports.
    ///
    /// context                     Current context
    /// numberRandomness            Number or ports to create
    /// startIndexFreshRandomness   Result that will hold the index of the first
    ///                                 port added by this function
    /// sharedAndDuplicatedPorts    List of ports that should be extended
    void addRandomnessPorts(
        mlir::MLIRContext *context,
        unsigned numberRandomness,
        unsigned *startIndexFreshRandomness,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts
    ){
        //Get a builder in that context
        mlir::OpBuilder builder(context);
        //Set current size as starting index of the fresh randomness
        *startIndexFreshRandomness = sharedAndDuplicatedPorts->size();
        //Create a type for the random input ports
        auto randType = secfir::RandomnessType::get(context, 1);
        //Add the specified number of randomness to the port list
        for(unsigned i=0; i<numberRandomness; i++){
            //Create a name for the random input port
            auto randPortName = builder.getStringAttr("_rand_" + std::to_string(i));
            //Add the port to the port list
            sharedAndDuplicatedPorts->push_back({randPortName, randType});
        }
    }

    /// Function that shares and duplicates a given instruction with a given
    /// operation builder. Operations that should be shared and are no SCA or
    /// CA gadgets must have the attribute "ToShare".
    ///
    /// op                          Operation to share and duplicate
    /// opBuilder                   Operation builder used for IR manipulation
    /// sharedModule                The module where the shared and duplicated
    ///                                 operation will be placed in
    /// oldClock                    Clock of the unshared and not duplicated module
    /// valueMap                    Map from values to their shared and duplicated
    ///                                 counterparts
    /// dummyMap                    Map for shared and duplicated dummy values
    /// numberShares                Number of shares to create
    /// numberDuplications          Number of duplications to create
    /// startIndexFreshRandomness   Index of the first randomness in the port list
    ///                                 of the shared module
    /// operationId                 An ID used to name a potential module of a gadget
    /// asModule                    If true the gadget is placed in a separate module 
    /// pipelineGadget              If true, the gadget is pipelined internally
    void shareAndDuplicateOperation(
        mlir::Operation &op,
        mlir::OpBuilder opBuilder,
        secfir::ModuleOp sharedModule,
        secfir::Value oldClock,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
        unsigned numberShares,
        unsigned numberDuplications,
        unsigned startIndexFreshRandomness,
        unsigned operationId,
        bool asModule,
        bool pipelineGadget
    ){
        bool supportedOperation = false;
        unsigned thisOperationNumberShares = 1;
        //Check whether operation should be shared
        if(op.getAttrOfType<mlir::IntegerAttr>("ToShare")){
            thisOperationNumberShares = numberShares;
        }
        //--Handle trivially shareable operations------------------------------
        if(secfir::isa<secfir::XorPrimOp>(op)){
            //Handle XOR operation
            shareAndDuplicateXor(
                    secfir::dyn_cast<secfir::XorPrimOp>(op), 
                    opBuilder, 
                    valueMap, 
                    dummyMap, 
                    thisOperationNumberShares, 
                    numberDuplications);
            supportedOperation = true;
        }else if(secfir::isa<secfir::NotPrimOp>(op)){
            //Handle not operation
            shareAndDuplicateNot(
                secfir::dyn_cast<secfir::NotPrimOp>(op),
                opBuilder,
                valueMap,
                dummyMap,
                thisOperationNumberShares,
                numberDuplications);
            supportedOperation = true;
        }else if(secfir::isa<secfir::RegOp>(op)){
            //Handle register operation
            shareAndDuplicateRegister(
                    secfir::dyn_cast<secfir::RegOp>(op),
                    opBuilder,
                    valueMap,
                    dummyMap,
                    thisOperationNumberShares,
                    numberDuplications);
            supportedOperation = true;
        }else if(secfir::isa<secfir::OutputOp>(op)){
            //Handle output operation
            //Save current insertion point of the operation builder
            auto insertionPoint = opBuilder.saveInsertionPoint();
            //Set insertion point to the end of the module
            opBuilder.setInsertionPointToEnd(sharedModule.getBodyBlock());
            //Share and duplicate operation
            shareAndDuplicateOutput(
                    secfir::dyn_cast<secfir::OutputOp>(op),
                    opBuilder, 
                    valueMap, 
                    thisOperationNumberShares, 
                    numberDuplications);
            //Reset insertion point to previouse setting
            opBuilder.restoreInsertionPoint(insertionPoint);
            supportedOperation = true;
        //--Handle SCA and CA gadgets------------------------------------------
        }else if(secfir::isa<secfir::PiniAndGadgetOp>(op) ||
                secfir::isa<secfir::SniPiniAndGadgetOp>(op) ||
                secfir::isa<secfir::SniAndGadgetOp>(op)
        ){
            //Handle SCA binary gadgets
            insertDuplicatedBinaryGadget(
                    op,
                    opBuilder,
                    valueMap,
                    dummyMap,
                    sharedModule.getArguments(),
                    oldClock,
                    startIndexFreshRandomness,
                    numberShares,
                    numberDuplications,
                    operationId,
                    asModule,
                    pipelineGadget);
            supportedOperation = true;
        }else if(secfir::isa<secfir::SniRefreshOp>(op)){
            //Handle SCA unary gadgets
            insertDuplicatedUnaryGadget(
                    op,
                    opBuilder,
                    valueMap,
                    dummyMap,
                    sharedModule.getArguments(),
                    oldClock,
                    startIndexFreshRandomness,
                    numberShares,
                    numberDuplications,
                    operationId,
                    asModule);
            supportedOperation = true;
        } else if(secfir::isa<secfir::CiniAndGadgetOp>(op) ||
                    secfir::isa<secfir::IciniAndGadgetOp>(op)){
            //Handle CA binary gadgets
            insertCombinedBinaryGadget(
                    op,
                    opBuilder,
                    valueMap,
                    dummyMap,
                    sharedModule.getArguments(),
                    oldClock,
                    startIndexFreshRandomness, 
                    numberShares,
                    numberDuplications,
                    operationId,
                    asModule,
                    pipelineGadget);
            supportedOperation = true;
        //--Handle operations that can be duplicated only----------------------
        }else{
            if(thisOperationNumberShares > 1){
                op.emitError() << "shareAndDuplicateOperation: tried to trivially share a nonlinear operation!";
                return;
            }
            if(secfir::isa<secfir::AndPrimOp>(op) ||
                    secfir::isa<secfir::OrPrimOp>(op)){
                //Handle nonlinear binary operations
                duplicateBinaryOp(
                        op,
                        opBuilder,
                        valueMap,
                        dummyMap,
                        numberDuplications);
                supportedOperation = true;
            }
        }
        //Ensure that only supported operations are handled
        if(!supportedOperation){
            op.emitError() << "shareAndDuplicateOperation: unsupported operation occurred!!";
        }
    }

    /// Function that shares and duplicates a register operation by creating a new register
    /// for each share and duplication index.
    ///
    /// regOp               Register to be shared and duplicated
    /// opBuilder           Operation builder that is used for operation creation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateRegister(
            secfir::RegOp regOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    ){
        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAdDuplicatedResult(
                        numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesSrc(
                        numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummySrc = false;
        //Check whether a dummy operation is required for the input
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(regOp.input()) == 0) dummySrc = true;
        //Create a register for each share and duplication
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                //Get the input for this share and duplication index. Either the 
                //real input, create a dummy operation, or take an existing dummy operation
                mlir::Value src;
                if(!dummySrc){
                    src = valueMap[regOp.input()][shareId][duplicationId];
                }else{
                    if(dummyMap.count(regOp.input()) == 0){
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                regOp.getLoc(),
                                regOp.result().getType(),
                                dummyValue);
                        src = constOp.getResult();
                    }else{
                        src = dummyMap[regOp.input()][shareId][duplicationId];
                    }
                }
                secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                //Give the register a name with the share and duplication index
                mlir::StringAttr name;
                if(numberShares > 1){
                    if(numberDuplications > 1){
                        name = opBuilder.getStringAttr(
                                regOp.nameAttr().getValue().str() + "_s" + 
                                std::to_string(shareId) + "_d" + std::to_string(duplicationId));
                    } else{
                        name = opBuilder.getStringAttr(
                                regOp.nameAttr().getValue().str() + "_s" + 
                                std::to_string(shareId));
                    }
                }else{
                    name = opBuilder.getStringAttr(
                                regOp.nameAttr().getValue().str() + 
                                 "_d" + std::to_string(duplicationId));
                }
                //Create new operation
                auto newOp = opBuilder.create<secfir::RegOp>(
                    regOp.getLoc(), 
                    type, 
                    src, 
                    valueMap[regOp.clockVal()][0][duplicationId],
                    name);
                //Copy all attributes to the new operation, except for the 
                //consumed "ToShare" attribute. This will remove the given 
                //name, so we have to set this again
                newOp.setAttrs(regOp.getAttrs());
                newOp.setAttr("name", name);                
                newOp.removeAttr("ToShare");
                //Add result share to the result vector
                sharedAdDuplicatedResult[shareId][duplicationId] = newOp.getResult();
                //Add possible dummy values to the corresponding vector
                if(dummySrc) dummyValuesSrc[shareId][duplicationId] = newOp.input();
                //Move insertion point for next operation
                opBuilder.setInsertionPointAfter(newOp);
            }
        }
        //Map the result shares to the result signal of the old module
        valueMap[regOp.getResult()] = sharedAdDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummySrc) dummyMap[regOp.input()] = dummyValuesSrc;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(regOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[regOp.getResult()][shareId][duplicationId].replaceAllUsesWith(
                                sharedAdDuplicatedResult[shareId][duplicationId]);
                    dummyMap[regOp.getResult()][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }
    }

    /// Function that shares and duplicates a NOT operation by
    /// inverting the share with domain ID 0 and forwarding all other shares. 
    ///
    /// notOp               The unshared not operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMAp            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares to create
    /// numberDuplications  The number of duplications to create
    void shareAndDuplicateNot(
            secfir::NotPrimOp notOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    ){
        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAndDuplicatedResult(
                        numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValues(
                        numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummy = false;
        //Check whether a dummy operation is required for the input
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(notOp.input()) == 0) dummy = true;

        const unsigned shareZero = 0;
        //Create a not operation for the first share and all duplications
        for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
            //Get the input for this share and duplication index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            mlir::Value input;
            if(!dummy){
                input = valueMap[notOp.input()][shareZero][duplicationId];
            }else{
                if(dummyMap.count(notOp.input()) == 0){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            notOp.getLoc(),
                            notOp.result().getType(),
                            dummyValue);
                    input = constOp.getResult();
                }else{
                    input = dummyMap[notOp.input()][shareZero][duplicationId];
                }
            }
            secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareZero, duplicationId);
            //Create new operation
            auto newOp = opBuilder.create<secfir::NotPrimOp>(
                        notOp.getLoc(), type, input);
            //Copy all attributes to the new operation, except for the 
            //consumed "ToShare" attribute
            newOp.setAttrs(notOp.getAttrs());
            newOp.removeAttr("ToShare");
            //Move insertion point for next operation
            opBuilder.setInsertionPointAfter(newOp);
            //Set result for the first share of this duplication
            sharedAndDuplicatedResult[shareZero][duplicationId] = newOp.getResult();
            //For all other shares we simply forward the input
            for(unsigned shareId=1; shareId<numberShares; shareId++){
               if(!dummy){
                sharedAndDuplicatedResult[shareId][duplicationId] = 
                            valueMap[notOp.input()][shareId][duplicationId];
                }else{
                    if(dummyMap.count(notOp.input()) == 0){
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                notOp.getLoc(),
                                notOp.result().getType(),
                                dummyValue);
                        sharedAndDuplicatedResult[shareId][duplicationId] = constOp.getResult();
                    }else{
                        sharedAndDuplicatedResult[shareId][duplicationId] = 
                                    dummyMap[notOp.input()][shareId][duplicationId];
                    }
                } 
            }        
        }
        //Map the result shares to the result signal of the old module
        valueMap[notOp.getResult()] = sharedAndDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummy) dummyMap[notOp.input()] = dummyValues;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(notOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[notOp.getResult()][shareId][duplicationId].replaceAllUsesWith(
                                sharedAndDuplicatedResult[shareId][duplicationId]);
                    dummyMap[notOp.getResult()][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }

    }

    /// Function that shares and duplicated an XOR operation by 
    /// creating a seperat instance for each share and duplication.
    ///
    /// xorOp               The unshared xor operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateXor(
            secfir::XorPrimOp xorOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    ){
        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAndDuplicatedResult(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesRhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> dummyValuesLhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(xorOp.lhs()) == 0) dummyLhs = true;
        if(valueMap.count(xorOp.rhs()) == 0) dummyRhs = true;
        //Get the input shares and create a new XOR operation for each share
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                //Get the left hand input for this share and duplication index. Either the 
                //real input, create a dummy operation, or take an existing dummy operation
                mlir::Value lhs;
                if(!dummyLhs){
                    lhs = valueMap[xorOp.lhs()][shareId][duplicationId];
                }else{
                    if(dummyMap.count(xorOp.lhs()) == 0){
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                xorOp.getLoc(),
                                xorOp.getResult().getType(),
                                dummyValue);
                        lhs = constOp.getResult();
                    }else{
                        lhs = dummyMap[xorOp.lhs()][shareId][duplicationId];
                    }
                }
                //Get the left hand input for this share and duplication index. Either the 
                //real input, create a dummy operation, or take an existing dummy operation
                mlir::Value rhs;
                if(!dummyRhs){
                    rhs = valueMap[xorOp.rhs()][shareId][duplicationId];
                }else{
                    if(dummyMap.count(xorOp.rhs()) == 0){
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                xorOp.getLoc(),
                                xorOp.getResult().getType(),
                                dummyValue);
                        rhs = constOp.getResult();
                    }else{
                        rhs = dummyMap[xorOp.rhs()][shareId][duplicationId];
                    }
                }
                secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                //Create new operation
                auto newOp = opBuilder.create<secfir::XorPrimOp>(
                            xorOp.getLoc(), type, lhs, rhs);
                //Copy all attributes to the new operation, except for the 
                //consumed "ToShare" attribute
                newOp.setAttrs(xorOp.getAttrs());
                newOp.removeAttr("ToShare");

                //Add result share to the result vector
                sharedAndDuplicatedResult[shareId][duplicationId] = newOp.getResult();
                //Add possible dummy values to the corresponding vector
                if(dummyLhs) dummyValuesLhs[shareId][duplicationId] = newOp.lhs();
                if(dummyRhs) dummyValuesRhs[shareId][duplicationId] = newOp.rhs();
                //Move insertion point for next operation
                opBuilder.setInsertionPointAfter(newOp);
            }
        }
        //Map the result shares to the result signal of the old module
        valueMap[xorOp.getResult()] = sharedAndDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[xorOp.lhs()] = dummyValuesLhs;
        if(dummyRhs) dummyMap[xorOp.rhs()] = dummyValuesRhs;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(xorOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[xorOp.getResult()][shareId][duplicationId].replaceAllUsesWith(
                                sharedAndDuplicatedResult[shareId][duplicationId]);
                    dummyMap[xorOp.getResult()][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }
    }

    /// Function that shares  and duplicates an output operation 
    /// by marking all shares and duplications as outputs.
    ///
    /// outputOp            The unshared output operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateOutput(
        secfir::OutputOp outputOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &oldToNewValueMap,
        unsigned numberShares,
        unsigned numberDuplications
    ){
        //Create a vector with all output shares
        mlir::SmallVector<mlir::Value, 1> outputValues;
        for(auto output : outputOp.getOperands()){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    outputValues.push_back(oldToNewValueMap[output][shareId][duplicationId]);
                }
            }
        }
        opBuilder.create<secfir::OutputOp>(outputOp.getLoc(), outputValues);
    }

    /// Function that inserts the logic of a binary gadget instead
    /// of a the correspondng gadget  operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create   
    /// gadgetId                    An ID used to name a module of the gadget
    /// asModule                    If true the gadget is placed in a separate module
    /// pipelineGadget              If true, gadget is pipelined internally
    void insertDuplicatedBinaryGadget(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            mlir::Value oldClock,
            unsigned startIndexFreshRandomness,
            unsigned numberShares,
            unsigned numberDuplications,
            unsigned gadgetId,
            bool asModule,
            bool pipelineGadget
    ){
        //Get values specific to the gadgets
        mlir::Value gadgetLhs;
        mlir::Value gadgetRhs;
        mlir::Value gadgetResult;
        mlir::ArrayAttr gadgetAttr;
        if(secfir::isa<secfir::PiniAndGadgetOp>(op)){
            secfir::PiniAndGadgetOp gadget = secfir::dyn_cast<secfir::PiniAndGadgetOp>(op);
            gadgetLhs = gadget.lhs();
            gadgetRhs = gadget.rhs();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        }else if(secfir::isa<secfir::SniPiniAndGadgetOp>(op)){
            secfir::SniPiniAndGadgetOp gadget = secfir::dyn_cast<secfir::SniPiniAndGadgetOp>(op);
            gadgetLhs = gadget.lhs();
            gadgetRhs = gadget.rhs();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        }else if(secfir::isa<secfir::SniAndGadgetOp>(op)){
            secfir::SniAndGadgetOp gadget = secfir::dyn_cast<secfir::SniAndGadgetOp>(op);
            gadgetLhs = gadget.lhs();
            gadgetRhs = gadget.rhs();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        }else{
            //Throw an error if an unsupported gadget should be placed
            assert(false && "unsupported gadget");
        }

        //Get the attribute of the gadget that indicates which randomness bits to use
        ///mlir::ArrayAttr arrayAttr = op.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        std::vector<mlir::Attribute> randIndices = gadgetAttr.getValue().vec();
        //Get a vector of randomness values for this gadget
        std::vector<mlir::Value> randomness(randIndices.size());
        for(unsigned i=0; i<randIndices.size(); i++){
            randomness[i] = moduleArguments[
               startIndexFreshRandomness + 
               randIndices.at(i).dyn_cast<mlir::IntegerAttr>().getInt()];
        }

        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAdDuplicatedResult(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesRhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> dummyValuesLhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(gadgetLhs) == 0) dummyLhs = true;
        if(valueMap.count(gadgetRhs) == 0) dummyRhs = true;
        //Get the corresponding circuit operation
        secfir::CircuitOp circuit;
        if(secfir::isa<secfir::CircuitOp>(op.getParentOp()->getParentOp())){
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp());
        }else{
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp()->getParentOp());
        }
        
        
        //Get the input shares and create a new XOR operation for each share
        for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
            //Get the left hand input for this share and duplication index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            std::vector<mlir::Value> sharedLhs(numberShares);
            if(!dummyLhs){
                for(unsigned shareId=0; shareId<numberShares; shareId++){
                    sharedLhs[shareId] = valueMap[gadgetLhs][shareId][duplicationId];
                }  
            }else{
                if(dummyMap.count(gadgetLhs) == 0){
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                op.getLoc(),
                                type,
                                dummyValue);
                        sharedLhs[shareId] = constOp.getResult();
                        dummyValuesLhs[shareId][duplicationId] = constOp.getResult();
                    }
                }else{
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        sharedLhs[shareId] = dummyMap[gadgetLhs][shareId][duplicationId];
                    }
                }
            }
            //Get the left hand input for this share and duplication index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            std::vector<mlir::Value> sharedRhs(numberShares);
            if(!dummyRhs){
                for(unsigned shareId=0; shareId<numberShares; shareId++){
                    sharedRhs[shareId] = valueMap[gadgetRhs][shareId][duplicationId];
                }  
            }else{
                if(dummyMap.count(gadgetRhs) == 0){
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                op.getLoc(),
                                type,
                                dummyValue);
                        sharedRhs[shareId] = constOp.getResult();
                        dummyValuesRhs[shareId][duplicationId] = constOp.getResult();
                    }
                }else{
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        sharedRhs[shareId] = dummyMap[gadgetRhs][shareId][duplicationId];
                    }
                }
            }
            //Place gadget logic
            std::vector<mlir::Value> sharedResult(numberShares);
            if(secfir::isa<secfir::PiniAndGadgetOp>(op)){
                StringAttr gadgetType = op.getAttrOfType<StringAttr>("GadgetType");
                //Insert the gadget as module if required
                if(asModule){
                    //Check whether a module for HPC2 already exist
                    //and insert a new one if necessary
                    if(!circuit.lookupSymbol("HPC2_Module")){
                        insertScaGadgetAsModule(
                            circuit.getLoc(),
                            op,
                            circuit,
                            opBuilder,
                            numberShares,
                            randomness.size(),
                            pipelineGadget);
                    }
                    //Insert an instance of the HPC2 gadget
                    insertInstanceOfScaGadget(
                        op.getLoc(),
                        opBuilder.getStringAttr("_hpc2_" + std::to_string(gadgetId)),
                        opBuilder.getSymbolRefAttr("HPC2_Module"),
                        opBuilder,
                        sharedLhs,
                        sharedRhs,
                        randomness,
                        sharedResult,
                        valueMap[oldClock][0][duplicationId],
                        false);

                }else{
                //Otherwise place the logic of HPC2 
                    if(gadgetType.getValue() == "HPC_1"){
                        placeHPC1(
                            op.getLoc(),
                            opBuilder,
                            sharedLhs,
                            sharedRhs,
                            sharedResult,
                            randomness,
                            valueMap[oldClock][0][duplicationId],
                            pipelineGadget);                    
                    } else  if(gadgetType.getValue() == "HPC_2"){   
                        placeHPC2(
                            op.getLoc(),
                            opBuilder,
                            sharedLhs,
                            sharedRhs,
                            sharedResult,
                            randomness,
                            valueMap[oldClock][0][duplicationId],
                            pipelineGadget);
                    }
                }
            }else if(secfir::isa<secfir::SniPiniAndGadgetOp>(op)){
                //Insert the gadget as module if required
                if(asModule){
                    //Check whether a module for HPC2+ already exist
                    //and insert a new one if necessary
                    if(!circuit.lookupSymbol("HPC2_Plus_Module")){
                        insertScaGadgetAsModule(
                            circuit.getLoc(),
                            op,
                            circuit,
                            opBuilder,
                            numberShares,
                            randomness.size(),
                            pipelineGadget);
                    }
                    //Insert an instance of the HPC2+ gadget
                    insertInstanceOfScaGadget(
                        op.getLoc(),
                        opBuilder.getStringAttr("_hpc2_plus_" + std::to_string(gadgetId)),
                        opBuilder.getSymbolRefAttr("HPC2_Plus_Module"),
                        opBuilder,
                        sharedLhs,
                        sharedRhs,
                        randomness,
                        sharedResult,
                        valueMap[oldClock][0][duplicationId],
                        false);

                }else{
                    //Otherwise place the logic of HPC2    
                    std::vector<mlir::Value> sharedRes(numberShares);
                    placeHPC2(
                        op.getLoc(),
                        opBuilder,
                        sharedLhs,
                        sharedRhs,
                        sharedRes,
                        randomness,
                        valueMap[oldClock][0][duplicationId],
                        pipelineGadget);
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                    //Add a register to the output to make the gadget SNI
                        secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                                opBuilder.getContext(), 1, shareId, duplicationId);
                        auto regOut = opBuilder.create<secfir::RegOp>(
                                op.getLoc(), 
                                type, 
                                sharedRes[shareId], 
                                valueMap[oldClock][0][duplicationId],
                                opBuilder.getStringAttr("_hpc_out_s" + 
                                            std::to_string(shareId)+"_d"+
                                            std::to_string(duplicationId)));
                        sharedResult[shareId] = regOut.getResult();
                    }
                }
            }else if(secfir::isa<secfir::SniAndGadgetOp>(op)){
                //Insert the gadget as module if required
                if(asModule){
                    //Check whether a module for DOM already exist
                    //and insert a new one if necessary
                    if(!circuit.lookupSymbol("DOM_Module")){
                        insertScaGadgetAsModule(
                            circuit.getLoc(),
                            op,
                            circuit,
                            opBuilder,
                            numberShares,
                            randomness.size(),
                            false);
                    }
                    //Insert an instance of the HPC2+ gadget
                    insertInstanceOfScaGadget(
                        op.getLoc(),
                        opBuilder.getStringAttr("_dom_" + std::to_string(gadgetId)),
                        opBuilder.getSymbolRefAttr("DOM_Module"),
                        opBuilder,
                        sharedLhs,
                        sharedRhs,
                        randomness,
                        sharedResult,
                        valueMap[oldClock][0][duplicationId],
                        false);

                }else{
                    //Place the logic of DOM 
                    placeDomMultiplication(
                        op.getLoc(),
                        opBuilder,
                        sharedLhs,
                        sharedRhs,
                        sharedResult,
                        randomness,
                        valueMap[oldClock][0][duplicationId]);
                }
            }
            //Set the output of the gadget for all shares
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                sharedAdDuplicatedResult[shareId][duplicationId] = sharedResult[shareId];
            }
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        op.removeAttr("ToShare");
        //Map the result shares to the result signal of the old module
        valueMap[gadgetResult] = sharedAdDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[gadgetLhs] = dummyValuesLhs;
        if(dummyRhs) dummyMap[gadgetRhs] = dummyValuesRhs;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadgetResult) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[gadgetResult][shareId][duplicationId].replaceAllUsesWith(
                                sharedAdDuplicatedResult[shareId][duplicationId]);
                    dummyMap[gadgetResult][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }
    }


    /// Function that inserts the duplicated logic of a unary gadget instead
    /// of a the correspondng gadget operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create   
    void insertDuplicatedUnaryGadget(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            mlir::Value oldClock,
            unsigned startIndexFreshRandomness,
            unsigned numberShares,
            unsigned numberDuplications,
            unsigned gadgetId,
            bool asModule
    ){
        //Get values specific to the gadgets
        mlir::Value gadgetInput;
        mlir::Value gadgetResult;
        mlir::ArrayAttr gadgetAttr;
        if(secfir::isa<secfir::SniRefreshOp>(op)){
            secfir::SniRefreshOp gadget = secfir::dyn_cast<secfir::SniRefreshOp>(op);
            gadgetInput = gadget.input();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        }else{
            //Throw an error if an unsupported gadget should be placed
            assert(false && "unsupported unary gadget");
        }
        //Get the corresponding circuit operation
        secfir::CircuitOp circuit;
        if(secfir::isa<secfir::CircuitOp>(op.getParentOp()->getParentOp())){
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp());
        }else{
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp()->getParentOp());
        }
        //Get the attribute of the gadget that indicates which randomness bits to use
        ///mlir::ArrayAttr arrayAttr = op.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        std::vector<mlir::Attribute> randIndices = gadgetAttr.getValue().vec();
        //Get a vector of randomness values for this gadget
        std::vector<mlir::Value> randomness(randIndices.size());
        for(unsigned i=0; i<randIndices.size(); i++){
            randomness[i] = moduleArguments[
               startIndexFreshRandomness + 
               randIndices.at(i).dyn_cast<mlir::IntegerAttr>().getInt()];
        }

        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAdDuplicatedResult(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesInput(numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummyInput = false;
        //Check whether a dummy operation is required for the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(gadgetInput) == 0) dummyInput = true; 
        //Get the input shares and create the gadget logic for all duplication
        for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
            //Get the input, either the real input, create a dummy operation, 
            //or take an existing dummy operation
            std::vector<mlir::Value> sharedInput(numberShares);
            if(!dummyInput){
                for(unsigned shareId=0; shareId<numberShares; shareId++){
                    sharedInput[shareId] = valueMap[gadgetInput][shareId][duplicationId];
                }  
            }else{
                if(dummyMap.count(gadgetInput) == 0){
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                op.getLoc(),
                                type,
                                dummyValue);
                        sharedInput[shareId] = constOp.getResult();
                        dummyValuesInput[shareId][duplicationId] = constOp.getResult();
                    }
                }else{
                    for(unsigned shareId=0; shareId<numberShares; shareId++){
                        sharedInput[shareId] = dummyMap[gadgetInput][shareId][duplicationId];
                    }
                }
            }
            //Place gadget logic
            std::vector<mlir::Value> sharedResult(numberShares);
            if(secfir::isa<secfir::SniRefreshOp>(op)){
                //Insert the gadget as module if required
                if(asModule){
                    //Check whether a module for HPC2 already exist
                    //and insert a new one if necessary
                    if(!circuit.lookupSymbol("DOM_Refresh_Module")){
                        insertScaGadgetAsModule(
                            circuit.getLoc(),
                            op,
                            circuit,
                            opBuilder,
                            numberShares,
                            randomness.size(),
                            false);
                    }
                    //Insert an instance of the HPC2 gadget
                    std::vector<mlir::Value> dummy;
                    insertInstanceOfScaGadget(
                        op.getLoc(),
                        opBuilder.getStringAttr("_dom_ref_" + std::to_string(gadgetId)),
                        opBuilder.getSymbolRefAttr("DOM_Refresh_Module"),
                        opBuilder,
                        sharedInput,
                        dummy,
                        randomness,
                        sharedResult,
                        valueMap[oldClock][0][duplicationId],
                        true);

                }else{
                    //Place the logic of HPC2
                    placeDomRefresh(
                        op.getLoc(),
                        opBuilder,
                        sharedInput,
                        sharedResult,
                        randomness,
                        valueMap[oldClock][0][duplicationId]);
                }
            }
            //Set the output of the gadget for all shares
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                sharedAdDuplicatedResult[shareId][duplicationId] = sharedResult[shareId];
            }
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        op.removeAttr("ToShare");
        //Map the result shares to the result signal of the old module
        valueMap[gadgetResult] = sharedAdDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyInput) dummyMap[gadgetInput] = dummyValuesInput;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadgetResult) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[gadgetResult][shareId][duplicationId].replaceAllUsesWith(
                                sharedAdDuplicatedResult[shareId][duplicationId]);
                    dummyMap[gadgetResult][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }
    }

    /// Function that inserts the logic of a binary CA gadget instead of the
    /// corresponding gadget operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create   
    /// gadgetId                    ID that will be used to name a potential module instance
    /// asModule                    If true, the gadget will be realized in separate module 
    /// pipelineGadget              If true, the gadget is pipelined internally
    void insertCombinedBinaryGadget(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            mlir::Value oldClock,
            unsigned startIndexFreshRandomness,
            unsigned numberShares,
            unsigned numberDuplications,
            unsigned gadgetId,
            bool asModule,
            bool pipelineGadget
    ){
        //Get values specific to the gadgets
        mlir::Value gadgetLhs;
        mlir::Value gadgetRhs;
        mlir::Value gadgetResult;
        mlir::ArrayAttr gadgetAttr;
        if(secfir::isa<secfir::CiniAndGadgetOp>(op)){
            secfir::CiniAndGadgetOp gadget = secfir::dyn_cast<secfir::CiniAndGadgetOp>(op);
            gadgetLhs = gadget.lhs();
            gadgetRhs = gadget.rhs();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        } else if(secfir::isa<secfir::IciniAndGadgetOp>(op)){
            secfir::IciniAndGadgetOp gadget = secfir::dyn_cast<secfir::IciniAndGadgetOp>(op);
            gadgetLhs = gadget.lhs();
            gadgetRhs = gadget.rhs();
            gadgetResult = gadget.getResult();
            gadgetAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        }else{
            //Throw an error if an unsupported gadget should be placed
            assert(false && "unsupported gadget");
        }

        //Get the attribute of the gadget that indicates which randomness bits to use
        ///mlir::ArrayAttr arrayAttr = op.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        std::vector<mlir::Attribute> randIndices = gadgetAttr.getValue().vec();
        //Get a vector of randomness values for this gadget
        std::vector<mlir::Value> randomness(randIndices.size());
        for(unsigned i=0; i<randIndices.size(); i++){
            randomness[i] = moduleArguments[
               startIndexFreshRandomness + 
               randIndices.at(i).dyn_cast<mlir::IntegerAttr>().getInt()];
        }
        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> sharedAndDuplicatedResult(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> *sharedAndDuplicatedLhs;
        std::vector<std::vector<mlir::Value>> *sharedAndDuplicatedRhs;

        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesRhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> dummyValuesLhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(gadgetLhs) == 0) dummyLhs = true;
        if(valueMap.count(gadgetRhs) == 0) dummyRhs = true;
        //Get the corresponding circuit operation
        secfir::CircuitOp circuit;
        if(secfir::isa<secfir::CircuitOp>(op.getParentOp()->getParentOp())){
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp());
        }else{
            circuit = secfir::dyn_cast<secfir::CircuitOp>(
                        op.getParentOp()->getParentOp()->getParentOp());
        }
        //Get LHS of the gadget, either the real value, a dummy value or 
        //create new dummy value if necessary
        if(!dummyLhs){
            sharedAndDuplicatedLhs = &valueMap[gadgetLhs];
        }else if(dummyMap.count(gadgetLhs) != 0){
            sharedAndDuplicatedLhs = &dummyMap[gadgetLhs];
        }else{
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                op.getLoc(),
                                type,
                                dummyValue);
                        dummyValuesLhs[shareId][duplicationId] = constOp.getResult();
                }
            }
            sharedAndDuplicatedLhs = &dummyValuesLhs;
        }
        //Get RHS of the gadget, either the real value, a dummy value or 
        //create new dummy value if necessary
        if(!dummyRhs){
            sharedAndDuplicatedRhs = &valueMap[gadgetRhs];
        }else if(dummyMap.count(gadgetRhs) != 0){
            sharedAndDuplicatedRhs = &dummyMap[gadgetRhs];
        }else{
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                            opBuilder.getContext(), 1, shareId, duplicationId);
                        secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                                op.getLoc(),
                                type,
                                dummyValue);
                        dummyValuesRhs[shareId][duplicationId] = constOp.getResult();
                }
            }
            sharedAndDuplicatedRhs = &dummyValuesRhs;
        }
        //Get duplicated clock vector
        std::vector<mlir::Value> clock = valueMap[oldClock][0];

        if(secfir::isa<secfir::CiniAndGadgetOp>(op)){
            StringAttr gadgetType = op.getAttrOfType<StringAttr>("GadgetType");
            //Insert the gadget as module if required
            if(asModule){
                //Check whether a module for CINI multiplication already exist
                //and insert a new one if necessary
                if(!circuit.lookupSymbol("CINI_Mul_Module")){
                    insertCombinedGadgetAsModule(
                        circuit.getLoc(),
                        op,
                        circuit,
                        opBuilder,
                        numberShares,
                        numberDuplications,
                        randomness.size(),
                        pipelineGadget);
                }
                //Insert an instance of the CINI multiplication gadget
                //std::vector<mlir::Value> dummy;
                insertInstanceOfCombinedGadget(
                    op.getLoc(),
                    opBuilder.getStringAttr("_cini_module_" + std::to_string(gadgetId)),
                    opBuilder.getSymbolRefAttr("CINI_Mul_Module"),
                    opBuilder,
                    *sharedAndDuplicatedLhs,
                    *sharedAndDuplicatedRhs,
                    randomness,
                    sharedAndDuplicatedResult,
                    clock);
            }else{
                //Otherwise just place the logic of the
                //CINI multiplication here
                if(gadgetType.getValue() == "HPC_1"){
                    placeCiniHPC1(
                        op.getLoc(),
                        opBuilder,
                        *sharedAndDuplicatedLhs,
                        *sharedAndDuplicatedRhs,
                        sharedAndDuplicatedResult,
                        randomness,
                        clock,
                        pipelineGadget);
                }else if(gadgetType.getValue() == "HPC_2"){
                    placeCiniHPC2(
                        op.getLoc(),
                        opBuilder,
                        *sharedAndDuplicatedLhs,
                        *sharedAndDuplicatedRhs,
                        sharedAndDuplicatedResult,
                        randomness,
                        clock,
                        pipelineGadget);
                }
            }
        } else if(secfir::isa<secfir::IciniAndGadgetOp>(op)){
            //Insert the gadget as module if required
            if(asModule){
                //Check whether a module for ICINI multiplication already exist
                //and insert a new one if necessary
                if(!circuit.lookupSymbol("ICINI_Mul_Module")){
                    insertCombinedGadgetAsModule(
                        circuit.getLoc(),
                        op,
                        circuit,
                        opBuilder,
                        numberShares,
                        numberDuplications,
                        randomness.size(),
                        pipelineGadget);
                }
                //Insert an instance of the ICINI multiplication gadget
                insertInstanceOfCombinedGadget(
                    op.getLoc(),
                    opBuilder.getStringAttr("_icini_module_" + std::to_string(gadgetId)),
                    opBuilder.getSymbolRefAttr("ICINI_Mul_Module"),
                    opBuilder,
                    *sharedAndDuplicatedLhs,
                    *sharedAndDuplicatedRhs,
                    randomness,
                    sharedAndDuplicatedResult,
                    clock);
            }else{
                //Otherwise just place the logic of the
                //ICINI multiplication here
                placeIciniMultiplicationLogic(
                    op.getLoc(),
                    opBuilder,
                    *sharedAndDuplicatedLhs,
                    *sharedAndDuplicatedRhs,
                    sharedAndDuplicatedResult,
                    randomness,
                    clock,
                    pipelineGadget);
            }
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        op.removeAttr("ToShare");
        //Map the result shares to the result signal of the old module
        valueMap[gadgetResult] = sharedAndDuplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[gadgetLhs] = dummyValuesLhs;
        if(dummyRhs) dummyMap[gadgetRhs] = dummyValuesRhs;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadgetResult) != 0){
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                    dummyMap[gadgetResult][shareId][duplicationId].replaceAllUsesWith(
                                sharedAndDuplicatedResult[shareId][duplicationId]);
                    dummyMap[gadgetResult][shareId][duplicationId].getDefiningOp()->erase();
                }
            }
        }
    }

    /// Function that duplicates a binary (nonlinear) operation by 
    /// creating a seperat instance for each duplication.
    ///
    /// op                  The binary operation to duplicate
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberDuplications  The number of duplications
    void duplicateBinaryOp(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberDuplications
    ){
        //Set number of shares fix to one.
        const unsigned numberShares = 1;
        const unsigned shareId = 0;
        //Get inputs and results of the operation
        assert(op.getOperands().size() == 2 && "Must be binary operation!");
        mlir::Value opLhs = op.getOperand(0);
        mlir::Value opRhs = op.getOperand(1);
        assert(op.getResults().size() == 1 && "Must have exactly one result!");
        mlir::Value opResult = op.getResult(0);
        //Create a vector for the result shares
        std::vector<std::vector<mlir::Value>> duplicatedResult(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<std::vector<mlir::Value>> dummyValuesRhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> dummyValuesLhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(valueMap.count(opLhs) == 0) dummyLhs = true;
        if(valueMap.count(opRhs) == 0) dummyRhs = true;
        //Get the input shares and create a new XOR operation for each share
        for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
            //Get the left hand input for this share and duplication index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            mlir::Value lhs;
            if(!dummyLhs){
                lhs = valueMap[opLhs][shareId][duplicationId];
            }else{
                if(dummyMap.count(opLhs) == 0){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            op.getLoc(),
                            opResult.getType(),
                            dummyValue);
                    lhs = constOp.getResult();
                }else{
                    lhs = dummyMap[opLhs][shareId][duplicationId];
                }
            }
            //Get the left hand input for this share and duplication index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            mlir::Value rhs;
            if(!dummyRhs){
                rhs = valueMap[opRhs][shareId][duplicationId];
            }else{
                if(dummyMap.count(opRhs) == 0){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            op.getLoc(),
                            opResult.getType(),
                            dummyValue);
                    rhs = constOp.getResult();
                }else{
                    rhs = dummyMap[opRhs][shareId][duplicationId];
                }
            }
            secfir::DuplicatedShareType type = secfir::DuplicatedShareType::get(
                        opBuilder.getContext(), 1, shareId, duplicationId);
            //Create new operation
            mlir::Operation *newOp;
            if(secfir::isa<secfir::AndPrimOp>(op)){
                newOp = opBuilder.create<secfir::AndPrimOp>(
                            op.getLoc(), type, lhs, rhs).getOperation();
            }else if(secfir::isa<secfir::OrPrimOp>(op)){
                newOp = opBuilder.create<secfir::OrPrimOp>(
                            op.getLoc(), type, lhs, rhs).getOperation();
            }
            //Copy all attributes to the new operation
            newOp->setAttrs(op.getAttrs());
            //Add result share to the result vector
            duplicatedResult[shareId][duplicationId] = newOp->getResult(0);
            //Add possible dummy values to the corresponding vector
            if(dummyLhs) dummyValuesLhs[shareId][duplicationId] = newOp->getOperand(0);
            if(dummyRhs) dummyValuesRhs[shareId][duplicationId] = newOp->getOperand(1);
            //Move insertion point for next operation
            opBuilder.setInsertionPointAfter(newOp);
        }
        
        //Map the result shares to the result signal of the old module
        valueMap[opResult] = duplicatedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[opLhs] = dummyValuesLhs;
        if(dummyRhs) dummyMap[opRhs] = dummyValuesRhs;
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(opResult) != 0){
            for(unsigned duplicationId=0; duplicationId<numberDuplications; duplicationId++){
                dummyMap[opResult][shareId][duplicationId].replaceAllUsesWith(
                            duplicatedResult[shareId][duplicationId]);
                dummyMap[opResult][shareId][duplicationId].getDefiningOp()->erase();
            } 
        }
    }

    // Function that inserts a module containing an SCA gadget at the 
    /// top of a given circuit. The gadgets can be HPC_2, HPC_2+, DOM
    /// multiplication, and DOM refresh. 
    ///
    /// location            Location of the new module
    /// op                  Operation defining the gadget type
    /// circuitOp           Circuit to which the module is added
    /// builder             An operation builder used for creation of the module
    /// numberShares        The number of input shares
    /// numberRandomness    The number of required randomness
    /// pipelineGadget      If true, gadget is pipelined internally
    void insertScaGadgetAsModule(
        mlir::Location location,
        mlir::Operation &op,
        secfir::CircuitOp &circuitOp,
        mlir::OpBuilder &builder,
        unsigned numberShares,
        unsigned numberRandomness,
        bool pipelineGadget
    ){
        bool unaryGadget = secfir::isa<secfir::SniRefreshOp>(op);
        //Create a list of input and output ports
        mlir::MLIRContext *context = builder.getContext();
        auto randomnessType = secfir::RandomnessType::get(context, 1);
        auto clockType = secfir::ClockType::get(context);
        secfir::SmallVector<secfir::ModulePortInfo, 4> ports;
        ports.push_back({builder.getStringAttr("clk"), clockType});
        for(unsigned i=0; i<numberShares; i++){
            auto shareType = secfir::ShareType::get(context, 1, i);
            mlir::StringAttr name = builder.getStringAttr("in_lhs_s" + std::to_string(i));
            ports.push_back({name, shareType});
        }
        if(!unaryGadget){
            for(unsigned i=0; i<numberShares; i++){
                auto shareType = secfir::ShareType::get(context, 1, i);
                mlir::StringAttr name = builder.getStringAttr("in_rhs_s" + std::to_string(i));
                ports.push_back({name, shareType});
            }
        }
        for(unsigned i=0; i<numberRandomness; i++){
            mlir::StringAttr name = builder.getStringAttr("in_rand" + std::to_string(i));
            ports.push_back({name, randomnessType});
        }
         for(unsigned i=0; i<numberShares; i++){
            auto shareType = secfir::ShareType::get(context, 1, i);
            auto flipType = secfir::FlipType::get(shareType);
            mlir::StringAttr name = builder.getStringAttr("out_res_s" + std::to_string(i));
            ports.push_back({name, flipType});
        }
        //Get the name of the module
        mlir::StringAttr moduleName;
        if(secfir::isa<secfir::SniPiniAndGadgetOp>(op)){
            moduleName = builder.getStringAttr("HPC2_Plus_Module");
        }else if(secfir::isa<secfir::PiniAndGadgetOp>(op)){
            moduleName = builder.getStringAttr("HPC2_Module");
        }else if(secfir::isa<secfir::SniAndGadgetOp>(op)){
            moduleName = builder.getStringAttr("DOM_Module");
        }else if(secfir::isa<secfir::SniRefreshOp>(op)){
            moduleName = builder.getStringAttr("DOM_Refresh_Module");
        }else{
            assert(false && "Unknown gadget!");
        }
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Get the input shares and randomness from the new module
        std::vector<mlir::Value> sharedLhs(numberShares);
        std::vector<mlir::Value> sharedRhs(numberShares);
        std::vector<mlir::Value> sharedRes(numberShares);
        std::vector<mlir::Value> randomness(numberRandomness);
        for(unsigned i=0; i<numberShares; i++){
            sharedLhs[i] = module.getBodyBlock()->getArgument(i+1);
        }
        if(!unaryGadget){
            for(unsigned i=0; i<numberShares; i++){
                sharedRhs[i] = module.getBodyBlock()->getArgument(i+1+numberShares);
            }
        }
        for(unsigned i=0; i<numberRandomness; i++){
            unsigned offset;
            if(unaryGadget) offset = 1+numberShares; 
            else offset = 1+2*(numberShares);
            randomness[i] = module.getBodyBlock()->getArgument(i+offset);
        }
        if(secfir::isa<secfir::PiniAndGadgetOp>(op) || 
                secfir::isa<secfir::SniPiniAndGadgetOp>(op)){
            StringAttr gadgetType = op.getAttrOfType<StringAttr>("GadgetType");
            if(gadgetType.getValue() == "HPC_1"){
                placeHPC1(
                    location,
                    builder,
                    sharedLhs,
                    sharedRhs,
                    sharedRes,
                    randomness,
                    module.getBodyBlock()->getArgument(0),
                    pipelineGadget);
            }else if(gadgetType.getValue() == "HPC_2"){
                //Place the logic of HPC2 in the new module
                placeHPC2(
                    location,
                    builder,
                    sharedLhs,
                    sharedRhs,
                    sharedRes,
                    randomness,
                    module.getBodyBlock()->getArgument(0),
                    pipelineGadget);
            }
        } else if(secfir::isa<secfir::SniAndGadgetOp>(op)){
            //Place the logic of DOM in the new module
            placeDomMultiplication(
                location,
                builder,
                sharedLhs,
                sharedRhs,
                sharedRes,
                randomness,
                module.getBodyBlock()->getArgument(0));
        }else if(secfir::isa<secfir::SniRefreshOp>(op)){
            placeDomRefresh(
                location,
                builder,
                sharedLhs,
                sharedRes,
                randomness,
                module.getBodyBlock()->getArgument(0));
        }
        if(secfir::isa<secfir::SniPiniAndGadgetOp>(op)){
            //Add a register to the output to make the gadget SNI
            std::vector<mlir::Value> sharedRegisterRes(numberShares);
            for(unsigned shareId=0; shareId<numberShares; shareId++){
                secfir::UIntType type = secfir::UIntType::get(builder.getContext(), 1);
                auto regOut = builder.create<secfir::RegOp>(
                        location, 
                        type, 
                        sharedRes[shareId], 
                        module.getBodyBlock()->getArgument(0),
                        builder.getStringAttr("_hpc_out_s" + std::to_string(shareId)));
                sharedRegisterRes[shareId] = regOut.getResult();
            }
            //Create a new output operation mapping the register outputs
            //to the module outputs
            builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    sharedRegisterRes);
        }else{
            //Create a new output operation mapping the gadget outputs 
            //to the module outputs
            builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    sharedRes);
        }
        //Erase the original output operation
        module.getOutputOp()->erase();

        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }

    /// Function that inserts a module containing a combined gadget at the 
    /// top of a given circuit. The gadgets can be a CINI multiplication.
    ///
    /// location            Location of the new module
    /// op                  Operation defining the gadget type
    /// circuitOp           Circuit to which the module is added
    /// builder             An operation builder used for creation of the module
    /// numberShares        The number of input shares
    /// numberRandomness    The number of required randomness
    /// pipelineGadget      If true, the gadget is pipelined internally
    void insertCombinedGadgetAsModule(
        mlir::Location location,
        mlir::Operation &op,
        secfir::CircuitOp &circuitOp,
        mlir::OpBuilder &builder,
        unsigned numberShares,
        unsigned numberDuplications,
        unsigned numberRandomness,
        bool pipelineGadget
    ){
        //Create a list of input and output ports
        mlir::MLIRContext *context = builder.getContext();
        auto randomnessType = secfir::RandomnessType::get(context, 1);
        auto clockType = secfir::ClockType::get(context);
        secfir::SmallVector<secfir::ModulePortInfo, 4> ports;
        for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
            mlir::StringAttr name = builder.getStringAttr(
                            "clk_" + std::to_string(duplicateId)); 
            ports.push_back({name, clockType});
        }
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                auto type = secfir::DuplicatedShareType::get(context, 1, shareId, duplicateId);
                mlir::StringAttr name = builder.getStringAttr(
                            "in_lhs_s" + std::to_string(shareId) + "_d" + std::to_string(duplicateId));
                ports.push_back({name, type});
            }
        }
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                auto type = secfir::DuplicatedShareType::get(context, 1, shareId, duplicateId);
                mlir::StringAttr name = builder.getStringAttr(
                            "in_rhs_s" + std::to_string(shareId) + "_d" + std::to_string(duplicateId));
                ports.push_back({name, type});
            }
        }
        for(unsigned i=0; i<numberRandomness; i++){
            mlir::StringAttr name = builder.getStringAttr("in_rand" + std::to_string(i));
            ports.push_back({name, randomnessType});
        }
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                auto type = secfir::DuplicatedShareType::get(context, 1, shareId, duplicateId);
                auto flipType = secfir::FlipType::get(type);
                mlir::StringAttr name = builder.getStringAttr(
                            "out_res_s" + std::to_string(shareId) + "_d" + std::to_string(duplicateId));
                ports.push_back({name, flipType});
            }
        }
        //Get the name of the module
        mlir::StringAttr moduleName;
        if(secfir::isa<secfir::CiniAndGadgetOp>(op)){
            moduleName = builder.getStringAttr("CINI_Mul_Module");
        }else if(secfir::isa<secfir::IciniAndGadgetOp>(op)){
            moduleName = builder.getStringAttr("ICINI_Mul_Module");
        }else{
            assert(false && "Unknown gadget!");
        }
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Get the input shares and randomness from the new module
        std::vector<std::vector<mlir::Value>> sharedLhs(numberShares, 
                                        std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> sharedRhs(numberShares, 
                                        std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<mlir::Value>> sharedRes(numberShares, 
                                        std::vector<mlir::Value>(numberDuplications));
        std::vector<mlir::Value> randomness(numberRandomness);
        std::vector<mlir::Value> duplicatedClock(numberDuplications);
        unsigned portIndex = 0;
        for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
            duplicatedClock[duplicateId] = module.getBodyBlock()->getArgument(portIndex);
            portIndex++;
        }
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                sharedLhs[shareId][duplicateId] = module.getBodyBlock()->getArgument(portIndex);
                portIndex++;
            }
        }
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                sharedRhs[shareId][duplicateId] = module.getBodyBlock()->getArgument(portIndex);
                portIndex++;
            }
        }
        for(unsigned i=0; i<numberRandomness; i++){
            randomness[i] = module.getBodyBlock()->getArgument(portIndex);
            portIndex++;
        }
        if(secfir::isa<secfir::CiniAndGadgetOp>(op)){
            StringAttr gadgetType = op.getAttrOfType<StringAttr>("GadgetType");
            if(gadgetType.getValue() == "HPC_1"){
                placeCiniHPC1(
                    location,
                    builder,
                    sharedLhs,
                    sharedRhs,
                    sharedRes,
                    randomness,
                    duplicatedClock,
                    pipelineGadget);
            }else if(gadgetType.getValue() == "HPC_2"){
                placeCiniHPC2(
                    location,
                    builder,
                    sharedLhs,
                    sharedRhs,
                    sharedRes,
                    randomness,
                    duplicatedClock,
                    pipelineGadget);
            }
        }else if(secfir::isa<secfir::IciniAndGadgetOp>(op)){
            placeIciniMultiplicationLogic(
                location,
                builder,
                sharedLhs,
                sharedRhs,
                sharedRes,
                randomness,
                duplicatedClock,
                pipelineGadget);
        }
        //Flatten result
        portIndex = 0;
        std::vector<mlir::Value> results(numberDuplications*numberShares);
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            for(unsigned duplicateId=0; duplicateId<numberDuplications; duplicateId++){
                results[portIndex] = sharedRes[shareId][duplicateId];
                portIndex++;
            }
        }
        //Create a new output operation mapping the gadget outputs 
        //to the module outputs
        builder.create<secfir::OutputOp>(
                module.getLoc(),
                results);
     
        //Erase the original output operation
        module.getOutputOp()->erase();

        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }


    /// Fuction that inserts an instance of an SCA gadget
    /// that ins realized as module. For unary gadgets 
    /// sharedRhs can be an empty list.
    ///
    ///location             Location of the instantiation
    ///instanceName         A name for the instance
    ///moduleName           Name of the referenced module
    ///builder              A builder for IR creation
    ///sharedLhs            Shared first input of the gadget
    ///sharedRhs            Shared second input of the gadget
    ///randomness           List of random values for the gadget
    ///sharedResult         Place to store the results, needs to 
    ///                         be initialized to numberOfShare elements
    ///clock                The clock signal to use
    void insertInstanceOfScaGadget(
        mlir::Location location,
        mlir::StringAttr instanceName,
        mlir::FlatSymbolRefAttr moduleName,
        mlir::OpBuilder &builder,
        std::vector<mlir::Value> &sharedLhs,
        std::vector<mlir::Value> &sharedRhs,
        std::vector<mlir::Value> &randomness,
        std::vector<mlir::Value> &sharedResult,
        mlir::Value &clock,
        bool unaryGadget
    ){
        //Get a list with all inputs to the gadget
        std::vector<mlir::Value> inputs;
        inputs.push_back(clock);
        for(unsigned i=0; i<sharedLhs.size(); i++)
            inputs.push_back(sharedLhs[i]);
        if(!unaryGadget){
            for(unsigned i=0; i<sharedRhs.size(); i++)
                inputs.push_back(sharedRhs[i]);
        }
        for(unsigned i=0; i<randomness.size(); i++)
            inputs.push_back(randomness[i]);
        mlir::ValueRange valRange(inputs);
        //Get a list with all output types of the gadget        
        //auto type = secfir::UIntType::get(builder.getContext(), 1);
        std::vector<mlir::Type> types;
        for(unsigned i=0; i<sharedLhs.size(); i++){
            auto shareType = secfir::ShareType::get(builder.getContext(), 1, i);
            types.push_back(shareType);
        }
        mlir::TypeRange typeRange(types);
        //Create an instance of the gadget module
        secfir::InstanceOp instance = builder.create<secfir::InstanceOp>(
            location,
            typeRange,
            instanceName,
            moduleName,
            valRange);
        //Set the shared results of the gadget
        for(unsigned i=0; i<sharedLhs.size(); i++){
            sharedResult[i] = instance.getResult(i);
        }
    }

    ///Fuction that inserts an instance of a combined SCA gadget
    ///that ins realized as module.
    ///
    ///location             Location of the instantiation
    ///instanceName         A name for the instance
    ///moduleName           Name of the referenced module
    ///builder              A builder for IR creation
    ///sharedLhs            Shared first input of the gadget
    ///sharedRhs            Shared second input of the gadget
    ///randomness           List of random values for the gadget
    ///sharedResult         Place to store the results, needs to 
    ///                         be initialized to numberOfShare elements
    ///duplicatedClock      List of clock signals to use
    void insertInstanceOfCombinedGadget(
        mlir::Location location,
        mlir::StringAttr instanceName,
        mlir::FlatSymbolRefAttr moduleName,
        mlir::OpBuilder &builder,
        std::vector<std::vector<mlir::Value>> &sharedLhs,
        std::vector<std::vector<mlir::Value>> &sharedRhs,
        std::vector<mlir::Value> &randomness,
        std::vector<std::vector<mlir::Value>> &sharedResult,
        std::vector<mlir::Value> &duplicatedClock
    ){
        //Get a list with all inputs to the gadget
        std::vector<mlir::Value> inputs;
        for(unsigned i=0; i<duplicatedClock.size(); i++)
            inputs.push_back(duplicatedClock[i]);
        for(unsigned i=0; i<sharedLhs.size(); i++)
            for(unsigned j=0; j<sharedLhs[i].size(); j++)
                inputs.push_back(sharedLhs[i][j]);
        for(unsigned i=0; i<sharedRhs.size(); i++)
            for(unsigned j=0; j<sharedRhs[i].size(); j++)
                inputs.push_back(sharedRhs[i][j]);
        for(unsigned i=0; i<randomness.size(); i++)
            inputs.push_back(randomness[i]);
        mlir::ValueRange valRange(inputs);
        //Get a list with all output types of the gadget        
        //auto type = secfir::UIntType::get(builder.getContext(), 1);
        std::vector<mlir::Type> types;
        for(unsigned shareId=0; shareId<sharedLhs.size(); shareId++){
            for(unsigned duplicateId=0; duplicateId<sharedLhs[shareId].size(); duplicateId++){
                auto duplicatedShareType = secfir::DuplicatedShareType::get(
                                builder.getContext(), 1, shareId, duplicateId);
                types.push_back(duplicatedShareType);
            }
        }
        mlir::TypeRange typeRange(types);
        //Create an instance of the gadget module
        secfir::InstanceOp instance = builder.create<secfir::InstanceOp>(
            location,
            typeRange,
            instanceName,
            moduleName,
            valRange);
        //Set the shared results of the gadget
        unsigned portIndex = 0;
        for(unsigned shareId=0; shareId<sharedLhs.size(); shareId++){
            for(unsigned duplicateId=0; duplicateId<sharedLhs[shareId].size(); duplicateId++){
                sharedResult[shareId][duplicateId] = instance.getResult(portIndex);
                portIndex++;
            }
        }
    }
}
}