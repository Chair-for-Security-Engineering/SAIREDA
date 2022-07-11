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
#include "Passes/TransformationPasses.h"

#include<set>
#include<tuple>
#include<math.h>
#include<algorithm>

namespace circt{
namespace secfir{

using namespace circt; 

    /// Transformation pass that replaces every AND gate with a 
    /// side-channel secure gadget.
    void secfir::InsertGadgetsPass::runOnOperation() {
        llvm::errs() << "---Insert Gadget Pass---\n";
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &module : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(module)){
                secfir::ModuleOp m = secfir::dyn_cast<secfir::ModuleOp>(module);
                //Go through all combinatorial logic blocks withing this module
                unsigned blockIndex = 0;
                for (auto &op : m.getBodyBlock()->getOperations()) {
                    if(secfir::isa<secfir::CombLogicOp>(op)){
                        secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(op);
                        //Increase statistic of existing combinatorial blocks
                        overallStatistic++;
                        //Create a list for operations that should be erased at the end
                        std::vector<mlir::Operation*> deleteOperations;
                        llvm::errs() << "Block " << blockIndex << ": Replace gates with gadgets...";
                        for (auto &internalOp : logicBlock.getBodyBlock()->getOperations()) {
                            //All AND operations should be replaced with a gadget
                            if(secfir::isa<secfir::AndPrimOp>(internalOp)){
                                secfir::AndPrimOp andOp = secfir::dyn_cast<secfir::AndPrimOp>(internalOp);
                                //Set an insertion point after the AND operation
                                builder.setInsertionPointAfter(andOp);
                                //Handle insertion of double-SNI gadgets
                                if(parameterMaskingType == MaskingMethod::doubleSni){   
                                    insertDoubleSniMultiplication(andOp, builder);
                                    refSniGadgetsStatistic++;
                                    mulSniGadgetsStatistic++;
                                //Handle insertion of PINI gadgets
                                }else if(parameterMaskingType == MaskingMethod::pini){
                                    insertPiniMultiplication(andOp, builder);
                                    piniGadgetsStatistic++;
                                //Handle insertion of SPINI gadgets
                                 }else if(parameterMaskingType == MaskingMethod::spini){
                                    insertSpiniMultiplication(andOp, builder);
                                    spiniGadgetsStatistic++;
                                //Handle insertion of SNI gadgets
                                }else if(parameterMaskingType == MaskingMethod::ni ||
                                            parameterMaskingType == MaskingMethod::sni ||
                                            parameterMaskingType == MaskingMethod::probSec ||
                                            parameterMaskingType== MaskingMethod::probSecNoTightProve){   
                                    insertSniMultiplication(&andOp, &builder);   
                                    mulSniGadgetsStatistic++; 
                                }
                                //Mark original or operation for removal
                                deleteOperations.push_back(&internalOp);
                            }
                        }
                        llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                        //Erase all operation that were replaced by gadgets
                        for(unsigned i=0; i<deleteOperations.size(); i++){
                            deleteOperations[i]->erase();
                        } 
                        //For PINI and doubleSNI gadgets nothing else is to do
                        if(parameterMaskingType == MaskingMethod::pini ||
                                parameterMaskingType == MaskingMethod::doubleSni){
                            //Mark current block as secure
                            secureBlockStatistic++;
                        //Run tightProver for probing security
                        }else if(parameterMaskingType == MaskingMethod::probSec){
                            //Set up an integer for the number of added refresh gadgets
                            unsigned numberRefGadgets = 0;
                            //Run constructive tightProver algorithm to make logic probing secure 
                            llvm::errs() << "Block " << blockIndex << ": Run TightProve... ";
                            tightProver(logicBlock, builder, &numberRefGadgets, true);
                            llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                            //Update the number of added refresh gadgets
                            refSniGadgetsStatistic += numberRefGadgets; 
                            //Verify that resulting design is probing secure
                            llvm::errs() << "Block " << blockIndex << ": Verify with TightProve... ";
                            if(!tightProver(logicBlock, builder, &numberRefGadgets, false)){
                                signalPassFailure();
                            }
                            llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                            //Mark current block as secure
                            secureBlockStatistic++;
                        //Refresh all intermediate values that are used more than once
                        //for NI
                        }else if(parameterMaskingType == MaskingMethod::ni ||
                                    parameterMaskingType == MaskingMethod::sni){
                            llvm::errs() << "Block " << blockIndex << ": Insert SNI REF... ";
                            unsigned numberRefGadgets = 0;
                            insertSniRefreshForNi(logicBlock, builder, &numberRefGadgets);
                            refSniGadgetsStatistic += numberRefGadgets;
                            
                            if(parameterMaskingType == MaskingMethod::sni){
                                bool test = checkSniOfNi(logicBlock.getBodyBlock()->getArguments()[0]);

                                mlir::Operation *outputOp = &(logicBlock.getBodyBlock()->getOperations().back());
                                for(mlir::Value outputValue: outputOp->getResults()){
                                    if(!checkSniOfNi(outputValue)){
                                        insertSniRefresh(&outputValue, outputOp, &builder);
                                        refSniGadgetsStatistic++;
                                    }
                                }
                            }
                            //Mark current block as secure
                            secureBlockStatistic++;
                            llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                        }     
                        blockIndex++;                 
                    }
                }   
            }
        }
    }

    void registerInsertGadgetsPass(){
        mlir::PassRegistration<InsertGadgetsPass>(
            "insert-gadgets", 
            "Replaces all AND gates with side-channel secure gadgets",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createInsertGadgetsPass();});
    }

    std::unique_ptr<mlir::Pass> createInsertGadgetsPass(){
	    return std::make_unique<InsertGadgetsPass>();
	}


        /// Function that creates a shared implementation of a given module.
    secfir::ModuleOp secfir::InsertGadgetsLogicPass::maskModule(
            secfir::ModuleOp &module, 
            std::vector<mlir::Attribute> toShare
    ){
        //Get builder for IR manipulation
        mlir::OpBuilder builder(&getContext());
        unsigned numberShares = parameterOrder+1;
        //Get input and output signals of original module
        secfir::SmallVector<secfir::ModulePortInfo, 4> oldPorts;
        module.getPortInfo(oldPorts);
        //Count number of ports that should be shared.
        //Number of 1's (ASCII) in encoding
        unsigned numberOfSharedPorts = 0;
        for(unsigned i=0; i<oldPorts.size(); i++)
            if(toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()) numberOfSharedPorts++;
        //Create a new list for input and output ports, where the defined port can 
        //be shared
        secfir::SmallVector<secfir::ModulePortInfo, 8> newPorts;
        newPorts.reserve(oldPorts.size()+numberOfSharedPorts*(numberShares-1));
        //Go though all ports and create the defined number of shares if necessary
        for(unsigned i=0; i<oldPorts.size(); i++){
            auto &port = oldPorts[i];
            //Check whether current port should be shared 
            //(encoding bit set to 1 (ASCII))
            if(toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                for(unsigned share=0; share<numberShares; share++){
                    //Create a name for the share
                    auto nameShare = builder.getStringAttr(
                        port.name.getValue().str() + "_" + std::to_string(share));
                    int32_t width;
                    //Get width of the port
                    if(port.type.isa<secfir::FlipType>()){
                        secfir::FlipType fType = port.type.dyn_cast<secfir::FlipType>();
                        width = fType.getElementType().getBitWidthOrSentinel();
                        
                        newPorts.push_back({
                            nameShare, 
                            secfir::FlipType::get(secfir::ShareType::get(&getContext(), width, share))});
                    }else{
                        width = port.type.getBitWidthOrSentinel();
                        newPorts.push_back({
                            nameShare, 
                            secfir::ShareType::get(&getContext(), width, share)});
                    }
                    //Push share to port list
                    // newPorts.push_back({
                    //         nameShare, 
                    //         secfir::ShareType::get(&getContext(), width, share)});
                }                   
                for(mlir::Operation* inst : module.getArguments()[i].getUsers()){
                    auto shareIt = builder.getBoolAttr(true);
                    inst->setAttr("ToShare", shareIt);
                }
            }else{
                //If port is not shared push original port to list
                newPorts.push_back({port.name, port.type});
            }
        }
        //Add ports for refreshing randomness
        // unsigned numberRand = getNumberOfRequiredRandomness(
        //             module.getBodyBlock(), numberShares);
        unsigned numberRand = module.getAttrOfType<mlir::IntegerAttr>("RequiredRandomness").getInt();
        for(unsigned i=0; i<numberRand; i++){
            //Create a name random input port
            auto randPortName = builder.getStringAttr("_rand_" + std::to_string(i));
            auto randType = secfir::RandomnessType::get(&getContext(), 1);
            newPorts.push_back({randPortName, randType});
        }
        //Get the index of the first randomness input port
        unsigned startIndexFreshRandomness = oldPorts.size() +
                numberOfSharedPorts*(numberShares-1);

        //Create shares for the outputs
        //Currently we share all outputs
        auto typeAttr = module.getAttrOfType<mlir::TypeAttr>(
                    secfir::ModuleOp::getTypeAttrName());
        mlir::FunctionType fnType = typeAttr.getValue().cast<mlir::FunctionType>();
        auto resultNames = module.getAttrOfType<mlir::ArrayAttr>("resultNames");
        auto resultTypes = fnType.getResults();
        for(size_t i=0; i<resultTypes.size(); i++){
            secfir::FlipType fType = resultTypes[i].dyn_cast<secfir::FlipType>();
            int32_t width = fType.getElementType().getBitWidthOrSentinel();
            std::string name = resultNames[i].cast<mlir::StringAttr>().getValue().str();
            for(unsigned share=0; share<numberShares; share++){
                auto nameShare = builder.getStringAttr(
                            name + "_" + std::to_string(share));
                newPorts.push_back({
                        nameShare, 
                        secfir::FlipType::get(secfir::ShareType::get(&getContext(), width, share))});
            }
        }
        
        //Create a new module with the new port list
        builder.setInsertionPoint(module);
        auto nameAttr = builder.getStringAttr(module.getName());
        secfir::ModuleOp newModule = builder.create<secfir::ModuleOp>(
            module.getLoc(), nameAttr, newPorts);

        //Create a map between the SSA values of the old module and those of the new 
        //module
        unsigned mapSize = module.getBodyBlock()->getOperations().size();
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> oldToNewValueMap(mapSize);
        unsigned j = 0; //Index for the new module list
        //Go though the list of input ports of the old module
        for(unsigned i=0; i<oldPorts.size(); i++){
            if(!toShare.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                //Add a single value to the mapping, if the port is not shared
                std::vector<mlir::Value> singleValue(1);
                singleValue[0] = newModule.getArguments()[j];
                oldToNewValueMap[module.getArguments()[i]] = singleValue;
                j++;
            }else{ //Encoding bit is 1 (ASCII)
                //Add the different shares to the mapping for shared ports
                std::vector<mlir::Value> sharedValue(numberShares);
                for(unsigned s=0; s<numberShares; s++){
                    sharedValue[s] = newModule.getArguments()[j];
                    j++;
                } 
                oldToNewValueMap[module.getArguments()[i]] = sharedValue;
                //Update list of parallel shares for all the created shares
                for(mlir::Value share : sharedValue){
                    //Get an instance of the current share domain
                    secfir::ShareType shareType;
                    if(share.getType().isa<secfir::ShareType>()){
                        shareType = share.getType().dyn_cast<
                                    secfir::ShareType>();
                    }else{                        
                        secfir::FlipType fType = share.getType().dyn_cast<secfir::FlipType>();
                        shareType = fType.getElementType().dyn_cast<secfir::ShareType>();
                    }
                    //Add all parallel shares to the list of parallel shares
                    for(mlir::Value parallelShare : sharedValue){
                        //Ignore the same share
                        if(parallelShare == share) continue;
                        //Add the parallel share to the list of the current share
                        shareType.setParallelShare(share, parallelShare);
                    }
                }
            }
        }


        //Create a list for operations that should be erased at the end
        mlir::OpBuilder opBuilder(newModule.body());
        std::vector<mlir::Operation*> deleteOperations;
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> dummyMap;
        bool nothingToShare = false;
        //Mark current terminator operation for deletion (will be replaced
        //by new one)
        for(auto &searchOp : newModule.getBodyBlock()->getOperations()){
            if(secfir::dyn_cast<secfir::OutputOp>(searchOp)){
                deleteOperations.push_back(&searchOp);
            }
        }
        while(!nothingToShare){
            nothingToShare = true;
            
            //Walk though module body and creat shared operation if necessary
            for (auto &op : module.getBodyBlock()->getOperations()) {
                //Check whether operation should be shared
                if(op.getAttrOfType<mlir::IntegerAttr>("ToShare")){
                    if(secfir::dyn_cast<secfir::ConnectOp>(op)) {
                        //Handle Connect operation
                        shareConnect(secfir::dyn_cast<secfir::ConnectOp>(op), 
                                opBuilder, oldToNewValueMap, numberShares);
                        nothingToShare = false;
                    }else if(secfir::isa<secfir::RegOp>(op)){
                        //Handle Registers
                        shareRegister(secfir::dyn_cast<secfir::RegOp>(op), 
                                opBuilder, oldToNewValueMap, dummyMap, numberShares);
                        deleteOperations.push_back(&op);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::NotPrimOp>(op)){
                        //Handle NOT operation
                        shareNot(secfir::dyn_cast<secfir::NotPrimOp>(op), 
                                opBuilder, oldToNewValueMap, dummyMap, numberShares);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::XorPrimOp>(op)){
                        //Handle XOR operation
                        shareXor(secfir::dyn_cast<secfir::XorPrimOp>(op), 
                                opBuilder, oldToNewValueMap, dummyMap, numberShares);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::NodeOp>(op)){
                        shareNode(secfir::dyn_cast<secfir::NodeOp>(op),
                                opBuilder, oldToNewValueMap, dummyMap, numberShares);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::PiniAndGadgetOp>(op)){
                        //Handle PINI multiplication
                        insertHPC2(secfir::dyn_cast<secfir::PiniAndGadgetOp>(op),
                                numberShares, opBuilder, oldToNewValueMap, dummyMap,
                                newModule.getArguments(), startIndexFreshRandomness);
                        nothingToShare = false;
                     }else if(secfir::dyn_cast<secfir::SniPiniAndGadgetOp>(op)){
                        //Handle SPINI multiplication
                        insertHPC2withOutputRegister(secfir::dyn_cast<secfir::SniPiniAndGadgetOp>(op),
                                numberShares, opBuilder, oldToNewValueMap, dummyMap,
                                newModule.getArguments(), startIndexFreshRandomness);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::SniAndGadgetOp>(op)){
                        //Handle SNI multiplication
                        insertDOMAnd(secfir::dyn_cast<secfir::SniAndGadgetOp>(op),
                                numberShares, opBuilder, oldToNewValueMap, dummyMap,
                                newModule.getArguments(), startIndexFreshRandomness);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::SniRefreshOp>(op)){
                        //Handle SNI refresh
                        insertDOMRefresh(secfir::dyn_cast<secfir::SniRefreshOp>(op),
                                numberShares, opBuilder, oldToNewValueMap, dummyMap,
                                newModule.getArguments(), startIndexFreshRandomness);
                        nothingToShare = false;
                    }else if(secfir::dyn_cast<secfir::OutputOp>(op)){
                        auto insertionPoint = opBuilder.saveInsertionPoint();
                        opBuilder.setInsertionPointToEnd(newModule.getBodyBlock());
                        shareOutput(secfir::dyn_cast<secfir::OutputOp>(op),
                                opBuilder, oldToNewValueMap, numberShares);
                        nothingToShare = false;
                        opBuilder.restoreInsertionPoint(insertionPoint);
                    }
                }
            }   
        }
        //Erase all operation that were replaced by gadgets
        for(unsigned i=0; i<deleteOperations.size(); i++){
            deleteOperations[i]->erase();
        } 
        return newModule;
    }

    void secfir::InsertGadgetsLogicPass::runOnOperation() {
        //Get builder for IR manipulation
         mlir::OpBuilder builder(&getContext());
        // Setup a list of mapping from unmasked to masked modules
        mlir::DenseMap<mlir::Operation *, mlir::Operation *> oldToNewModuleMap;
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                //Mask module if some of the parts are marked to be shared
                if(module.getAttr("PortsToShare")){                    
                    mlir::ArrayAttr arrayAttr = 
                            module.getAttrOfType<mlir::ArrayAttr>("PortsToShare");
                    auto arrayRef = arrayAttr.getValue();
                    auto toShare = arrayRef.vec();
                    
                    oldToNewModuleMap[module] = maskModule(
                                module, 
                                toShare);
                }
            }
        }
        // Finally delete all the unmasked (old) modules.
        for (auto oldNew : oldToNewModuleMap){
            oldNew.first->dropAllUses();
            oldNew.first->dropAllDefinedValueUses();
            oldNew.first->dropAllReferences();
            oldNew.first->erase();
        }
    }

    void registerInsertGadgetsLogicPass(){
        mlir::PassRegistration<InsertGadgetsLogicPass>(
            "insert-gadget-logic", 
            "Replaces gadget operations by the corresponding logic",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createInsertGadgetsLogicPass();});
    }

    std::unique_ptr<mlir::Pass> createInsertGadgetsLogicPass(){
        return std::make_unique<InsertGadgetsLogicPass>();
    }

    // Add an attribute to the module that is a bitstring that
    // encodes which input and output ports should be shared.
    void secfir::SetShareAttribute::runOnOperation(){
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                //Get input and output signals of the module
                secfir::SmallVector<secfir::ModulePortInfo, 4> ports;
                module.getPortInfo(ports);

                mlir::OpBuilder builder(&getContext());
                std::vector<mlir::Attribute> toShareVec;
                //Go though all ports and decide whether they should be shared
                for(unsigned i=0; i<ports.size(); i++){
                    auto &port = ports[i];        
                    //Currently: Share everything except for clock and reset ports
                    if(port.name.getValue().str().find("reset") != std::string::npos || 
                    port.name.getValue().str().find("rst") != std::string::npos ||
                    port.type.getTypeID() == secfir::ResetType::getTypeID() ||
                    port.type.getTypeID() == secfir::ClockType::getTypeID()){
                        toShareVec.push_back(builder.getBoolAttr(false));
                    }else{
                        toShareVec.push_back(builder.getBoolAttr(true));
                    }
                }
                //Add the attribute to the module
                mlir::ArrayRef<mlir::Attribute> arrayRef(toShareVec);
                mlir::ArrayAttr toShareArrayAttr = builder.getArrayAttr(arrayRef);
                module.setAttr("PortsToShare", toShareArrayAttr);
            }
        }
    }
    void registerSetShareAttributePass(){
    mlir::PassRegistration<SetShareAttribute>(
        "set-share-attribute", 
        "Mark all input/ouput ports for sharing except for CLK and RST",
        []() -> std::unique_ptr<mlir::Pass>{return secfir::createSetShareAttributePass();});
    }

    std::unique_ptr<mlir::Pass> createSetShareAttributePass(){
        return std::make_unique<SetShareAttribute>();
    }
}
}