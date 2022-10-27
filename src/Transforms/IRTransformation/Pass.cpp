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
#include "Passes/IRTransformation.h"
#include "Passes/TransformationPasses.h"
#include "Util/util.h"

namespace circt{
namespace secfir{

using namespace circt; 
using namespace secfir;

    ///------------------------------------------------------------------------
    /// *** Insert Module Pass ***
    ///
    /// Pass that goes though all modules an replaces all operations or all 
    /// marked operations with an instance of an equivalent module.
    ///------------------------------------------------------------------------

    void InsertGateModule::runOnOperation() {
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Get current combinational logic operation
        //secfir::CombLogicOp logicBlock = getOperation();
        CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(isa<ModuleOp>(m)){
                ModuleOp module = dyn_cast<ModuleOp>(m);
                
                std::vector<mlir::Operation*> deleteOperations;
                unsigned andOp_index = 0;
                unsigned xorOp_index = 0;
                unsigned orOp_index = 0;
                unsigned notOp_index = 0;
                unsigned regOp_index = 0;
                //Go though all operations of that module
                for(auto &op : module.getBodyBlock()->getOperations()){
                    bool createBinaryModule = false;
                    bool createUnaryModule = false;
                    bool createRegisterModule = false;
                    bool createInstance = false;
                    std::string moduleName;
                    std::string instanceName;

                    if(isa<AndPrimOp>(op)){
                        //Prepare for AND operation
                        //Check whether only marked operations should be replaced
                        if(parameterReplaceMethod == ReplaceMethod::marked){
                            //Handle case where only marked operations should be replaced
                            if(op.hasAttr("ModuleReplace")){
                                //Create an instance only when the attribute is true
                                createInstance = op.getAttrOfType<mlir::BoolAttr>(
                                                    "ModuleReplace").getValue();
                                //Create a module only once
                                if(!circuit.lookupSymbol("AndModule")){
                                    createBinaryModule = createInstance;
                                }
                            }
                        }else{
                            //Handle case where all operations should be replaced
                            //Create a module only once
                            if(!circuit.lookupSymbol("AndModule")) createBinaryModule = true;
                            //Create an instanace always
                            createInstance = true;
                        }
                        //Increment the number of instanaces
                        if(createInstance) andOp_index++;
                        //Set the names of the module and instance
                        moduleName = "AndModule";
                        instanceName = "_and_module_" + std::to_string(andOp_index);
                    }else if(isa<XorPrimOp>(op)){
                        //Prepare for XOR operation
                        //Check whether only marked operations should be replaced
                        if(parameterReplaceMethod == ReplaceMethod::marked){
                            //Handle case where only marked operations should be replaced
                            if(op.hasAttr("ModuleReplace")){
                                //Create an instance only when the attribute is true
                                createInstance = op.getAttrOfType<mlir::BoolAttr>(
                                                    "ModuleReplace").getValue();
                                 //Create a module only once
                                if(!circuit.lookupSymbol("XorModule")){
                                    createBinaryModule = createInstance;
                                }
                            }
                        }else{
                            //Handle case where all operations should be replaced
                            //Create a module only once
                            if(!circuit.lookupSymbol("XorModule")) createBinaryModule = true;
                            //Create an instanace always
                            createInstance = true;
                        }
                        //Increment the number of instanaces
                        if(createInstance) xorOp_index++;
                        //Set the names of the module and instance
                        moduleName = "XorModule";
                        instanceName = "_xor_module_" + std::to_string(xorOp_index);
                    }else if(isa<OrPrimOp>(op)){
                        //Prepare for OR operation
                        //Check whether only marked operations should be replaced
                        if(parameterReplaceMethod == ReplaceMethod::marked){
                            //Handle case where only marked operations should be replaced
                            if(op.hasAttr("ModuleReplace")){
                                //Create an instance only when the attribute is true
                                createInstance = op.getAttrOfType<mlir::BoolAttr>(
                                                    "ModuleReplace").getValue();
                                if(!circuit.lookupSymbol("OrModule")){
                                    createBinaryModule = createInstance;
                                }
                            }
                        }else{
                            //Handle case where all operations should be replaced
                            //Create module only once
                            if(!circuit.lookupSymbol("OrModule")) createBinaryModule = true;
                            //Create an instanace always
                            createInstance = true;
                        }
                        //Increment the number of instanaces
                        if(createInstance) orOp_index++;
                        //Set the names of the module and instance
                        moduleName = "OrModule";
                        instanceName = "_or_module_" + std::to_string(orOp_index);
                    }else if(isa<NotPrimOp>(op)){
                        //Prepare for NOT operation
                        //Check whether only marked operations should be replaced
                        if(parameterReplaceMethod == ReplaceMethod::marked){
                            //Handle case where only marked operations should be replaced
                            if(op.hasAttr("ModuleReplace")){
                                //Create an instance only when the attribute is true
                                createInstance = op.getAttrOfType<mlir::BoolAttr>(
                                                    "ModuleReplace").getValue();
                                //Create a module only once
                                if(!circuit.lookupSymbol("NotModule")){
                                    createUnaryModule = createInstance;
                                }
                            }
                        }else{
                            //Handle case where all operations should be replaced
                            //Create a module only once
                            if(!circuit.lookupSymbol("NotModule")) createUnaryModule = true;
                            //Create an instanace always
                            createInstance = true;
                        }
                        //Increment the number of instanaces
                        if(createInstance) notOp_index++;
                        //Set the names of the module and instance
                        moduleName = "NotModule";
                        instanceName = "_not_module_" + std::to_string(notOp_index);
                    }else if(isa<RegOp>(op)){
                        //Prepare for Register operation
                        //Check whether only marked operations should be replaced
                        if(parameterReplaceMethod == ReplaceMethod::marked){
                            //Handle case where only marked operations should be replaced
                            if(op.hasAttr("ModuleReplace")){
                                //Create an instance only when the attribute is true
                                createInstance = op.getAttrOfType<mlir::BoolAttr>(
                                                    "ModuleReplace").getValue();
                                //Create a module only once
                                if(!circuit.lookupSymbol("RegModule")){
                                    createRegisterModule = createInstance;
                                }
                            }
                        }else{
                            //Handle case where all operations should be replaced
                            //Create a module only once
                             if(!circuit.lookupSymbol("RegModule")) createRegisterModule = true;
                             //Create an instanace always
                            createInstance = true;
                        }
                        //Increment the number of instanaces
                        if(createInstance) regOp_index++;
                        //Set the names of the module and instance
                        moduleName = "RegModule";
                        instanceName = "_reg_module_" + std::to_string(regOp_index);
                    }


                    //Create a new module if required
                    if(createBinaryModule){
                        insertBinaryModule(
                                op.getLoc(),
                                op,
                                builder.getStringAttr(moduleName),
                                circuit,
                                builder,
                                &getContext());
                    }else if(createUnaryModule){
                        insertUnaryModule(
                                op.getLoc(),
                                op,
                                builder.getStringAttr(moduleName),
                                circuit,
                                builder,
                                &getContext());
                    }else if(createRegisterModule){
                        insertRegisterModule(
                                op.getLoc(),
                                op,
                                builder.getStringAttr(moduleName),
                                circuit,
                                builder,
                                &getContext());
                    }
                    //Create an instance of a module if required
                    if(createInstance){
                        //Set insertion point
                        builder.setInsertionPointAfter(&op);
                        //Create instance operation
                        insertInstanceOfOperationModule(
                                op,
                                builder.getStringAttr(instanceName),
                                builder.getSymbolRefAttr(moduleName),
                                builder);
                        //Mark original operation for removal
                        deleteOperations.push_back(&op);
                    }
                }
                //Erase all operations marked for removal
                for(unsigned i=0; i<deleteOperations.size(); i++){
                    deleteOperations[i]->erase();
                }
            }
        }
    }

     void registerInsertGateModulePass(){
        mlir::PassRegistration<InsertGateModule>(
            "insert-module-pass", 
            "Pass that inserts operation modules",
            []() -> std::unique_ptr<mlir::Pass>{return createInsertGateModulePass();});
    }

    std::unique_ptr<mlir::Pass> createInsertGateModulePass(){
	    return std::make_unique<InsertGateModule>();
	}

    ///------------------------------------------------------------------------
    /// *** Insert Combinational Logic Hierarchy ***
    ///
    /// Pass that inserts the additional hierarchy of combinational logic block
    /// seperating combinational logic from registers.
    ///------------------------------------------------------------------------

    void InsertCombinationalNetworkHierarchy::runOnOperation() {
        llvm::errs() << "---Insert Combinational Networks---\n";
        //Get current module operation
        //secfir::FModuleOp module = getOperation();
        CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(isa<ModuleOp>(m)){
                ModuleOp module = dyn_cast<ModuleOp>(m);
        //Reset statistic of combinational logic blocks to zero
        //(we count only for the last module!)
        combLogicLayersStatistic = 0;
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Define a list that will contain all input values of each combinational network
        std::vector<std::vector<mlir::Value>> inputNetworks;
        inputNetworks.push_back(std::vector<mlir::Value>());
        //Define a list that will contain all output values of each combinational network
        std::vector<std::vector<mlir::Value>> outputNetworks;
        outputNetworks.push_back(std::vector<mlir::Value>());
        //Define a list that will contain all operations of each combinational network
        std::vector<std::vector<mlir::Operation*>> operationNetworks;
        operationNetworks.push_back(std::vector<mlir::Operation*>());
        //Define a list that will contain all output register operation for each network 
        std::vector<std::vector<mlir::Operation*>> outputRegisterNetworks;
        outputRegisterNetworks.push_back(std::vector<mlir::Operation*>());
        //Define a list that will contain all connect operations for the network output
        std::vector<std::vector<mlir::Operation*>> outputConnectNetworks;
        outputConnectNetworks.push_back(std::vector<mlir::Operation*>());
        //Define a mapping from intermediate values to a combinational network
        mlir::DenseMap<mlir::Value, unsigned> valueToNetworkMap;
        //Define a list of points where the networks will be insterted
        std::vector<mlir::OpBuilder::InsertPoint> insertionPoints;
        insertionPoints.push_back(builder.saveInsertionPoint());
        //Define a map from values to outputs of combinational logic blocks
        mlir::DenseMap<mlir::Value, mlir::Value> outputNetworkMap;

        //Remove all loops in the design
        mlir::DenseMap<mlir::Value, mlir::Value> loopMap;
        removeLoops(
            builder,
            module.getBodyBlock()->getOperations(),
            loopMap);
        //Divide operations in different combinational networks by assigning an ID
        unsigned addedRegister = assignOperationToCombinationalNetwork(
                module.getBodyBlock()->getOperations(),
                module.getBodyBlock()->getArgument(0),
                builder,
                !parameterNoPipeline,
                valueToNetworkMap,
                inputNetworks,
                operationNetworks,
                outputNetworks,
                outputRegisterNetworks,
                insertionPoints
        );
        insertedRegisterStatistic =+ addedRegister;
        registerLayersStatistic = outputRegisterNetworks.size();

        unsigned networkId;    
        std::vector<mlir::Operation*> deleteOperations;   
        //Create the actual combinational network operations and fill them with the 
        //correspining operations
        for(networkId=0; networkId<inputNetworks.size(); networkId++){
            //Restore instertion point for this combinational network
            builder.restoreInsertionPoint(insertionPoints[networkId]);
            if(operationNetworks[networkId].size() == 0) {
                if(insertionPoints.size() > networkId+1){
                    insertionPoints[networkId+1] = builder.saveInsertionPoint(); 
                }
                continue;
            }
            //Ensure that all inputs are well defined!
            //If not pipelining is done than the input may be updated with
            //the output of a previous logic block
            if(parameterNoPipeline){
                for(unsigned i=0; i<inputNetworks[networkId].size(); i++){
                    if(inputNetworks[networkId][i].getDefiningOp() && 
                                !isa<RegOp>(inputNetworks[networkId][i].getDefiningOp()) &&
                                !isa<ConstantOp>(inputNetworks[networkId][i].getDefiningOp())){
                        inputNetworks[networkId][i] = outputNetworkMap[inputNetworks[networkId][i]];
                    }
                }
            }      
            //Get input and outputs of the network in the required form
            mlir::ArrayRef<mlir::Value> inputs(inputNetworks[networkId]);
            mlir::ArrayRef<mlir::Value> outputs(outputNetworks[networkId]);
            mlir::TypeRange typeRange(outputs);
            //Create a new combinational network operation
            CombLogicOp logicBlock = builder.create<CombLogicOp>(
                    operationNetworks[networkId][0]->getLoc(), typeRange, inputs);
            combLogicLayersStatistic++;
            //Set insertion point of builder to the begin of the new network
            builder.setInsertionPointToStart(logicBlock.getBodyBlock());
            //Create a mapping from the network input values to the intern 
            //input values of the network
            mlir::BlockAndValueMapping blockValueMapping;
            // blockValueMapping.clear();
            for(unsigned i=0; i<inputNetworks[networkId].size(); i++){
                blockValueMapping.map(
                            inputNetworks[networkId][i], 
                            logicBlock.getBodyBlock()->getArgument(i));
            }
            //Define a list of intern output values of the network
            mlir::SmallVector<mlir::Value, 0> outputComb;

            std::vector<mlir::Value> definedValues;
            for(auto input: inputs) definedValues.push_back(input);
            // std::vector<mlir::Operation*> deleteOperations;

            //Move all corresponding operations inside the network
            moveOperationsInsideCombinationalLogic(
                        builder,
                        networkId,
                        logicBlock,
                        operationNetworks[networkId],
                        definedValues,
                        blockValueMapping,
                        outputNetworks[networkId],
                        deleteOperations,
                        outputComb,
                        outputNetworkMap);
            //Create a terminator for the combinational network with corresponding outputs
            builder.create<OutputCombOp>(module.getLoc(), outputComb);
            //Overwrite insertion point of this network with the point after the network
            builder.setInsertionPointAfter(logicBlock);

            //Move output registers behind this network 
            mlir::Operation *temp = logicBlock;
            if(outputRegisterNetworks.size() > networkId){
                for(mlir::Operation* moveOp : outputRegisterNetworks[networkId]){
                    moveOp->moveAfter(temp);
                    temp = moveOp;
                    builder.setInsertionPointAfter(moveOp);
                }
            }
            //insertionPoints[networkId] = builder.saveInsertionPoint(); 
            //Place next combinational network after output registers of this network
            if(insertionPoints.size() > networkId+1){
                insertionPoints[networkId+1] = builder.saveInsertionPoint(); 
            }
        }
        //Add removed loops again
        for(auto loopVal: loopMap){
           loopVal.second.replaceAllUsesWith(loopVal.first);
           deleteOperations.push_back(loopVal.second.getDefiningOp());
        }
        //Delete old operation outside the network. Needs to be done after all 
        //operations where cloned to keep references correct.
        for(auto op : deleteOperations){
            op->erase();
        }
            }}
    }

     void registerInsertCombinationalNetworkHierarchyPass(){
        mlir::PassRegistration<InsertCombinationalNetworkHierarchy>(
            "insert-combinatorial-logic-hierarchy", 
            "Inserts combinatorial logic operations",
            []() -> std::unique_ptr<mlir::Pass>{return createInsertCombinationalNetworkHierarchyPass();});
    }

    std::unique_ptr<mlir::Pass> createInsertCombinationalNetworkHierarchyPass(){
	    return std::make_unique<InsertCombinationalNetworkHierarchy>();
	}

    ///------------------------------------------------------------------------
    /// *** Flatten Combinational Logic Hierarchy ***
    ///
    /// Pass that removes all CombLogicOp operations by copying all 
    /// instruction from inside the operation to after the operation. 
    ///------------------------------------------------------------------------

    void FlattenCombinationalNetworkHierarchy::runOnOperation(){
        //Get current module operation
        //secfir::FModuleOp module = getOperation();
        CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(isa<ModuleOp>(m)){
                ModuleOp module = dyn_cast<ModuleOp>(m);

        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Define a list that will contain the existing combinational networks
        std::vector<mlir::Operation*> networks;
        //Go through all operations of the module
        for (auto &op : module.getBodyBlock()->getOperations()) {
            //We are only interessted in CombLogicOps
            if(isa<CombLogicOp>(op)){
                //Get the operation as SecFIR CombLogicOp
                CombLogicOp combOp = dyn_cast<CombLogicOp>(op);
                //Set instertion point for new operations after the CombLogicOp
                builder.setInsertionPointAfter(combOp);
                //Create a mapping from the intern network input values to the extern
                //input values of the network
                mlir::BlockAndValueMapping blockValueMapping;
                for(unsigned i=0; i<combOp.input().size(); i++){
                    blockValueMapping.map(
                            combOp.getBodyBlock()->getArgument(i),
                            combOp.input()[i]
                           );
                }
                //Get the output operation of the network for mapping of the results
                OutputCombOp outputOp = dyn_cast<OutputCombOp>(
                            combOp.getBodyBlock()->back());

                //Copy operations form inside the network to outside the network
                for(auto &innerOp : combOp.getBodyBlock()->getOperations()){
                    //Only move the operation if it is not an output operaton of the network
                    if(!isa<OutputCombOp>(innerOp)){
                        mlir::Operation *newOp = builder.clone(innerOp, blockValueMapping);
                        builder.setInsertionPointAfter(newOp);
                        //Replace the uses of the output of the network with the correct values
                        for(unsigned i=0; i<outputOp.getNumOperands(); i++){
                            if(outputOp.getOperand(i) == innerOp.getResult(0)){
                                combOp.getResult(i).replaceAllUsesWith(newOp->getResult(0));
                            }
                        }
                    }
                }
                //Save the CombLogicOp for later removal
                networks.push_back(combOp.getOperation());
            }
        }
        //Delete not longer required combinational network operations
        for(auto combOp : networks){
            combOp->erase();
        }
            }}
    }

     void registerFlattenCombinationalNetworkHierarchyPass(){
        mlir::PassRegistration<FlattenCombinationalNetworkHierarchy>(
            "flatten-combinatorial-logic-hierarchy", 
            "Removes combinatorial logic operations",
            []() -> std::unique_ptr<mlir::Pass>{return createFlattenCombinationalNetworkHierarchyPass();});
    }

    std::unique_ptr<mlir::Pass> createFlattenCombinationalNetworkHierarchyPass(){
	    return std::make_unique<FlattenCombinationalNetworkHierarchy>();
	}
}
}