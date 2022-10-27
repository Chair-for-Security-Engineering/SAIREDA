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

    ///------------------------------------------------------------------------
    /// ***** Insert Gadget Pass *****
    ///
    /// Transformation pass that replaces every AND gate with a 
    /// side-channel secure gadget and inserts required refresh 
    /// gadgets.
    ///------------------------------------------------------------------------
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
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp);    
                                //Handle insertion of PINI gadgets
                                }else if(parameterMaskingType == MaskingMethod::pini){
                                    insertPiniMultiplication(andOp, builder);
                                    piniGadgetsStatistic++;
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp);   
                                //Handle insertion of SPINI gadgets
                                }else if(parameterMaskingType == MaskingMethod::spini){
                                    insertSpiniMultiplication(andOp, builder);
                                    spiniGadgetsStatistic++;
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp);  
                                //Handle insertion of CINI gadgets
                                }else if(parameterMaskingType == MaskingMethod::cini){
                                    insertCiniMultiplication(andOp, builder);
                                    ciniGadgetsStatistic++;
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp);   
                                //Handle insertion of ICINI gadgets
                                }else if(parameterMaskingType == MaskingMethod::icini){
                                    insertIciniMultiplication(andOp, builder);
                                    iciniGadgetsStatistic++;
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp); 
                                //Handle insertion of SNI gadgets
                                }else if(parameterMaskingType == MaskingMethod::ni ||
                                            parameterMaskingType == MaskingMethod::sni ||
                                            parameterMaskingType == MaskingMethod::probSec ||
                                            parameterMaskingType== MaskingMethod::probSecNoTightProve){   
                                    insertSniMultiplication(&andOp, &builder);   
                                    mulSniGadgetsStatistic++; 
                                    //Mark original or operation for removal
                                    deleteOperations.push_back(&internalOp);   
                                }
                            }
                        }
                        llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                        //Erase all operation that were replaced by gadgets
                        for(unsigned i=0; i<deleteOperations.size(); i++){
                            deleteOperations[i]->erase();
                        } 
                        //For PINI, CINI and doubleSNI gadgets nothing else is to do
                        if(parameterMaskingType == MaskingMethod::pini ||
                                parameterMaskingType == MaskingMethod::cini ||
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

    ///------------------------------------------------------------------------
    //// ***** Define Gadget Type Pass *****
    ///
    /// Pass that allows to define the type of a gadget,
    /// by adding an annotation to the according operation.
    ///------------------------------------------------------------------------
    void secfir::DefineGadgetTypePass::runOnOperation() {
        llvm::errs() << "---Define Gadget Type Pass---\n";
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Define gadget options
        StringAttr hpc1 = builder.getStringAttr("HPC_1");
        StringAttr hpc2 = builder.getStringAttr("HPC_2");
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &module : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(module)){
                secfir::ModuleOp m = secfir::dyn_cast<secfir::ModuleOp>(module);
                //Go through all combinatorial logic blocks withing this module
                for (auto &op : m.getBodyBlock()->getOperations()) {
                    if(secfir::isa<secfir::CombLogicOp>(op)){
                        secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(op);
                        for (auto &internalOp : logicBlock.getBodyBlock()->getOperations()) {
                            //Add an annotation depending on the compositional property and defined type
                            if(secfir::isa<CiniAndGadgetOp>(internalOp) || 
                                    secfir::isa<PiniAndGadgetOp>(internalOp)){
                                if(parameterGadgetType == GadgetType::hpc1){
                                    internalOp.setAttr("GadgetType", hpc1);   
                                }else if(parameterGadgetType == GadgetType::hpc2){
                                    internalOp.setAttr("GadgetType", hpc2);
                                }
                            }                        
                        }
                    }
                }
            }
        }
    }

    void registerDefineGadgetTypePass(){
        mlir::PassRegistration<DefineGadgetTypePass>(
            "define-gadget-type", 
            "Annotates each gadget with the defined type",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createDefineGadgetTypePass();});
    }

    std::unique_ptr<mlir::Pass> createDefineGadgetTypePass(){
	    return std::make_unique<DefineGadgetTypePass>();
	}

    ///------------------------------------------------------------------------
    //// ***** Insert Gadget-Logic Pass *****
    ///
    /// Transformation pass that creates a shared and duplicated
    /// design, by duplicating and inserting the logic of gadgets.
    ///------------------------------------------------------------------------
    void secfir::InsertGadgetsLogicPass::runOnOperation() {
        llvm::errs() << "---Insert-Gadget-Logic Pass---\n";
        //Get builder for IR manipulation
         mlir::OpBuilder builder(&getContext());
        // Setup a list of mapping from unmasked to masked modules
        mlir::DenseMap<mlir::Operation *, mlir::Operation *> oldToNewModuleMap;
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                std::vector<mlir::Attribute> toShare;
                //Get corresponding attribute if some ports are shared
                if(module.getAttr("PortsToShare")){                    
                    mlir::ArrayAttr arrayAttr = 
                            module.getAttrOfType<mlir::ArrayAttr>("PortsToShare");
                    auto arrayRef = arrayAttr.getValue();
                    toShare = arrayRef.vec();
                    // oldToNewModuleMap[module] = maskModule(
                    //             module, 
                    //             toShare);
                } else{
                    //If no port is shared, create a vector of attributes 
                    //indicating that no port is shared
                    mlir::BoolAttr DontShareIt = builder.getBoolAttr(false);
                    for(unsigned i=0; i<module.getArguments().size(); i++){
                        toShare.push_back(DontShareIt);
                    }
                }
                //Create a new masked and duplicated module
                oldToNewModuleMap[module] = maskAndDuplicateModule(
                            module, 
                            toShare);
                
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



    /// Recursive function that marks all operations that depend on a 
    /// specified value for sharing, by setting an attribute "ToShare"
    /// to true.
    ///
    /// valueToShare        The value that should be shared
    /// shareIt             A boolean attribute set to true
    void markUsersForSharing(
        mlir::Value valueToShare,
        mlir::BoolAttr shareIt
    ){
        //Do the recursive calls and marking for all users of the specified value
        for(auto user : valueToShare.getUsers()){
            //For combinational logic blocks the marking has to be done for the 
            //users of the respective input to the logic block.
            if(secfir::isa<secfir::CombLogicOp>(user)){
                //Get a CombLogicOp
                secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(user);
                //Find the ID of the respective input to the logic block
                unsigned in_id = 0;
                for(; in_id<logicBlock.getOperands().size(); in_id++){
                    if(logicBlock.getOperands()[in_id] == valueToShare){
                        break;
                    }
                }
                //Mark all users of that input for sharing
                for(auto user_in_block: logicBlock.getBodyBlock()->getArguments()[in_id].getUsers()){
                    //Stop recursive calls if the operation is already marked for sharing
                    if(!user_in_block->hasAttrOfType<mlir::IntegerAttr>("ToShare")){
                        //Set ToShare attribute
                        user_in_block->setAttr("ToShare", shareIt); 
                        //Recursive calls for all results of that instruction
                        if(user->getResults().size() > 0){
                            for(auto res : user_in_block->getResults()){
                                markUsersForSharing(res, shareIt);
                            }
                        }
                    }
                }
            //For the output of an combinational logic block the marking has to be done
            //for the users of the respective output value
            } else if(secfir::isa<secfir::OutputCombOp>(user)){
                //Get the output operation and the corresponding logic block
                secfir::OutputCombOp combOut = secfir::dyn_cast<secfir::OutputCombOp>(user);
                secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(
                                combOut.getParentOp());
                //Mark the output operation for sharing
                combOut.setAttr("ToShare", shareIt);      
                //Find the ID of the respective output of the logic block  
                unsigned out_id=0;        
                for(; out_id<combOut.getOperands().size(); out_id++){
                    if(combOut.getOperands()[out_id] == valueToShare){
                        break;
                    }
                }
                //Mark all users of that output for sharing
                for(auto user_out_block: logicBlock.getResults()[out_id].getUsers()){
                    //Stop recursive calls if the operation is already marked for sharing
                    if(!user_out_block->hasAttrOfType<mlir::IntegerAttr>("ToShare")){
                        //Set ToShare attribute
                        user_out_block->setAttr("ToShare", shareIt);
                        //Recursive calls for all results of that operation
                        if(user_out_block->getResults().size() > 0){
                            for(auto res : user_out_block->getResults()){
                                markUsersForSharing(res, shareIt);
                            }
                        }
                    }
                }
            //For all other instructions all users are marked for sharing.
            //Stop recursive call if the operation is already marked for sharing
            }else if(!user->hasAttrOfType<mlir::IntegerAttr>("ToShare")){
                //Mark operation for sharing
                user->setAttr("ToShare", shareIt);
                //Recursive call for all results of that operation
                if(user->getResults().size() > 0){
                    for(auto res : user->getResults()){
                        markUsersForSharing(res, shareIt);
                    }
                }
            } 
        }
    }

    /// Pass that adds an attribute to the module that is a bitstring that
    /// encodes which input and output ports should be shared and marks all
    /// operations dependent on those inputs for sharing, with an attribute
    /// "ToShare".
    ///
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

                //Mark all operations dependent on shared inputs for sharing
                auto shareIt = builder.getBoolAttr(true);
                for(unsigned i=0; i<ports.size(); i++){
                    if(toShareVec.at(i).dyn_cast<mlir::BoolAttr>().getValue()){
                        //Call recursive function for setting the attribute         
                        markUsersForSharing(module.getArguments()[i], shareIt);
                    }
                }
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