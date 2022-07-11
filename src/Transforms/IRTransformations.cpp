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
#include "SecFIR/SecFIRDialect.h"
#include "Passes/TransformationPasses.h"

namespace circt{
namespace secfir{

using namespace circt;

    bool vectorContainsValue(
                std::vector<mlir::Value> vector, 
                mlir::Value search
    ){
        for(mlir::Value val : vector){
            if(val == search)
                return true;
        }
        return false;
    }

    bool vectorContainsOperation(
                std::vector<mlir::Operation*> vector, 
                mlir::Operation *search
    ){
        for(mlir::Operation* op : vector){
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

    /// An transformation pass that inserts CombLogicOp operations by finding combinational 
    /// networks within the module and combining them inside a CombLogicOp.
    void secfir::InsertCombinationalNetworkHierarchy::runOnOperation() {
        //Get current module operation
        //secfir::FModuleOp module = getOperation();
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);

        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Define a list that will contain all input values of each combinational network
        std::vector<std::vector<mlir::Value>> inputNetworks;
        inputNetworks.push_back(std::vector<mlir::Value>());
        //Define a list that counts the number of module input ports in the network inputs
        std::vector<unsigned> portsInInputs;
        portsInInputs.push_back(0);
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

        //Divide operations in different combinational networks by assigning an ID
        unsigned networkId = 0;
        for (auto &op : module.getBodyBlock()->getOperations()) {
            if(secfir::isa<secfir::RegOp>(op) || secfir::isa<secfir::RegInitOp>(op)){
               //Do no assignment for registers. This will be done in the connect
               //operation

                secfir::RegOp regOp = secfir::dyn_cast<secfir::RegOp>(op);
                //Get combinational network ID of input 
                networkId = valueToNetworkMap[regOp.input()];

                valueToNetworkMap[regOp.getResult()] = networkId + 1;
                //Create new layer of input/output values and operations for 
                //a new combinational network if it does not already exist
                if(inputNetworks.size() < networkId+2){
                    inputNetworks.push_back(std::vector<mlir::Value>());
                    portsInInputs.push_back(0);
                    outputNetworks.push_back(std::vector<mlir::Value>());
                    operationNetworks.push_back(std::vector<mlir::Operation*>());
                    outputRegisterNetworks.push_back(std::vector<mlir::Operation*>());
                    outputConnectNetworks.push_back(std::vector<mlir::Operation*>());
                    insertionPoints.push_back(builder.saveInsertionPoint());
                }
                //Add the register to the corresponding list of output register
                outputRegisterNetworks[networkId].push_back(regOp);
                //Add input of register operation to the outputs of the current network 
                if(regOp.input().getDefiningOp()){
                    outputNetworks[networkId].push_back(regOp.input());
                    //Set insertion point for network
                    builder.setInsertionPointAfterValue(regOp.input());
                    insertionPoints[networkId] = builder.saveInsertionPoint();
                }
                //Add output of register operation to the inputs of the next network
                if(regOp.getResult().getDefiningOp()){
                    inputNetworks[networkId+1].push_back(regOp.getResult()); 
                }
                for(mlir::Operation *user : regOp.getResult().getUsers()){
                    if(user->getResults().size() == 1){
                        if(valueToNetworkMap.count(user->getResults()[0])){
                            // user->dump();
                            inputNetworks[valueToNetworkMap[user->getResults()[0]]].push_back(regOp.getResult());
                        }
                    }
                }

            } else if(secfir::isa<secfir::ConnectOp>(op)){
                //Get SecFIR instance of current operation
                secfir::ConnectOp connectOp = secfir::dyn_cast<secfir::ConnectOp>(op);
                //Get combinational network ID of input 
                networkId = valueToNetworkMap[connectOp.src()];
                //Add the connect operation to the corresponding output connect list
                outputConnectNetworks[networkId].push_back(connectOp);
                //If the destiny is a register, set the network ID
                //of that register to source network ID + 1
                if(connectOp.dest().getDefiningOp()){
                    //The destiny is the module output port
                    //Increase the number module of input ports in the network input
                    portsInInputs[networkId]++;
                } 
                //Add input of connect operation to the outputs of the current network 
                if(connectOp.src().getDefiningOp()){
                    outputNetworks[networkId].push_back(connectOp.src());
                    //Set insertion point for network
                    builder.setInsertionPointAfterValue(connectOp.src());
                    insertionPoints[networkId] = builder.saveInsertionPoint();
                }
                //Add output of connect operation to the inputs of the next network
                if(connectOp.dest().getDefiningOp()){
                    inputNetworks[networkId+1].push_back(connectOp.dest()); 
                }
            } else if(secfir::isa<secfir::OutputOp>(op)){
                secfir::OutputOp outputOp = secfir::dyn_cast<secfir::OutputOp>(op);
                for(mlir::Value operand : outputOp.getOperands()){
                    networkId = valueToNetworkMap[operand];

                    if(operand.getDefiningOp()){
                        outputNetworks[networkId].push_back(operand);
                    }
                }


            }else if(op.getNumResults() == 1){
                mlir::OperandRange opOperands = op.getOperands();
                for(unsigned i=0; i<opOperands.size(); i++){
                    //Add input operand to input list of current network, if
                    //it is a module input and it is not already in the list
                    if(!opOperands[i].getDefiningOp()){ 
                        if(!vectorContainsValue(inputNetworks[0], opOperands[i])){
                            valueToNetworkMap[opOperands[i]] = 0;
                            inputNetworks[0].push_back(opOperands[i]);
                        }
                    }
                    //Set network ID to highest ID of inputs
                    if(valueToNetworkMap[opOperands[i]] > networkId){
                        networkId = valueToNetworkMap[opOperands[i]];
                    }
                    valueToNetworkMap[op.getResult(0)] = networkId;
                    //Add operation to the network with the correct ID
                    if(!vectorContainsOperation(operationNetworks[networkId], &op))
                        operationNetworks[networkId].push_back(&op);
                }
            }
            //Reset network ID
            networkId = 0;
        }
        //Create the actual combinational network operations and fill them with the 
        //correspining operations
        for(networkId=0; networkId<inputNetworks.size(); networkId++){
            if(operationNetworks[networkId].size() == 0) continue;
            //Restore instertion point for this combinational network
            builder.restoreInsertionPoint(insertionPoints[networkId]);
            //Get input and outputs of the network in the required form
            mlir::ArrayRef<mlir::Value> inputs(inputNetworks[networkId]);
            mlir::ArrayRef<mlir::Value> outputs(outputNetworks[networkId]);
            mlir::TypeRange typeRange(outputs);
            //Create a new combinational network operation
            secfir::CombLogicOp logicBlock = builder.create<secfir::CombLogicOp>(
                    operationNetworks[networkId][0]->getLoc(), typeRange, inputs);
            //Set insertion point of builder to the begin of the new network
            builder.setInsertionPointToStart(logicBlock.getBodyBlock());
            //Create a mapping from the network input values to the intern 
            //input values of the network
            mlir::BlockAndValueMapping blockValueMapping;
            for(unsigned i=0; i<inputNetworks[networkId].size(); i++){
                blockValueMapping.map(
                            inputNetworks[networkId][i], 
                            logicBlock.getBodyBlock()->getArgument(i));

                //Add mapping of parallel shares of other domains
                if(inputNetworks[networkId][i].getType().isa<secfir::ShareType>()){
                    //Get share type of current input
                    secfir::ShareType shareType = inputNetworks[networkId][i].getType().
                                dyn_cast<secfir::ShareType>();
                    //Iterate over all parallel shares of the current input
                    std::vector<mlir::Value> parallelShares = shareType.
                                getParallelShares(inputNetworks[networkId][i]);
                    for(mlir::Value parallelShare : parallelShares){
                        //Compare each parallel share with each ohter input and add
                        //a mapping for the combinational logic input if a match is found
                        for(unsigned j=0; j<inputNetworks[networkId].size(); j++){
                            if(parallelShare == inputNetworks[networkId][j]){
                                shareType.setParallelShare(
                                        logicBlock.getBodyBlock()->getArgument(i),
                                        logicBlock.getBodyBlock()->getArgument(j)
                                );
                                break;
                            }
                        }
                    }
                }
            }
            //Define a list of intern output values of the network
            mlir::SmallVector<mlir::Value, 0> outputComb;

            unsigned copyCount = 0;
            unsigned networkSize = operationNetworks[networkId].size();
            std::vector<mlir::Value> definedValues;
            for(auto input: inputs) definedValues.push_back(input);
            std::vector<mlir::Operation*> deleteOperations;
            //Move all corresponding operations inside the network
            while (copyCount < networkSize){
                       
                for(unsigned opIndex=0; opIndex < operationNetworks[networkId].size(); opIndex++){
                    auto op = operationNetworks[networkId][opIndex];
                    if(op != NULL){
                        bool copy = true;
                        for(auto operand : op->getOperands()){
                            if(!vectorContainsValue(definedValues, operand)){
                                copy = false;
                                break;
                            }
                        }
                        if(copy){
                            copyCount++;
                            definedValues.push_back(op->getOpResult(0));

                            //Clone operation into the network
                            mlir::Operation *newOp = builder.clone(*op, blockValueMapping);
                            //If the result is an network output the usage of the result must be 
                            //changed to the output of the network
                            unsigned index = 0;
                            if(vectorContainsValue(outputNetworks[networkId], op->getResult(0))){
                                //Get push result to the output vector and determine current index
                                index = outputComb.size();
                                outputComb.push_back(newOp->getResult(0));
                                //Determine usages of the result that are within the current network
                                SmallPtrSet<Operation *, 1> except;
                                for(mlir::Operation *use: op->getResult(0).getUsers()){
                                    if(use->getNumResults() == 1)
                                        if(valueToNetworkMap[use->getResult(0)] == networkId)
                                            except.insert(use);
                                }
                                //Replace all usages of the result that are not within this network
                                op->getResult(0).replaceAllUsesExcept(logicBlock.getResult(index),
                                        except);
                            }
                            //Set instertion point of the builder behind the new operation
                            builder.setInsertionPointAfter(newOp);

                            //--Update parallel share list
                            //Check whether type of the result of the old operation is a share type
                            if(op->getResult(0).getType().isa<secfir::ShareType>()){
                                //Get the share domain of the old operation result
                                secfir::ShareType type = 
                                            op->getResult(0).getType().dyn_cast<secfir::ShareType>();
                                //Update all parallel shares that are known
                                for(auto parallelShare : type.getParallelShares(op->getResult(0))){
                                    //Get share type (domain index) of the parallel share
                                    secfir::ShareType parallelType = 
                                                parallelShare.getType().dyn_cast<secfir::ShareType>();
                                    //Add the parallel share to the new operations parallel shares
                                    type.setParallelShare(newOp->getResult(0), parallelShare);
                                    //Change the parallel share of the parallel share from the 
                                    //old operation to the new operation
                                    parallelType.updateParallelShare(
                                                parallelShare, 
                                                op->getResult(0),
                                                newOp->getResult(0));
                                }
                            }
                            deleteOperations.push_back(op);
                            operationNetworks[networkId][opIndex] = NULL;
                        }
                    }
                }
            }
            //Delete old operation outside the network. Needs to be done after all 
            //operations where cloned to keep references correct.
            for(auto op : deleteOperations){
                op->erase();
            }
            //Create a terminator for the combinational network with corresponding outputs
            builder.create<secfir::OutputCombOp>(module.getLoc(), outputComb);
            //Overwrite insertion point of this network with the point after the network
            builder.setInsertionPointAfter(logicBlock);
            insertionPoints[networkId] = builder.saveInsertionPoint();   
        }
        //Move register and connection operation that are dependent on the network
        for(networkId=0; networkId<inputNetworks.size(); networkId++){
            builder.restoreInsertionPoint(insertionPoints[networkId]);
            for(mlir::Operation* moveOp : outputRegisterNetworks[networkId]){
                mlir::Operation *newOp = builder.clone(*moveOp);
                moveOp->replaceAllUsesWith(newOp);
                moveOp->erase();
                builder.setInsertionPointAfter(newOp);
            }
            for(mlir::Operation* moveOp : outputConnectNetworks[networkId]){
                mlir::Operation *newOp = builder.clone(*moveOp);
                moveOp->replaceAllUsesWith(newOp);
                moveOp->erase();
                builder.setInsertionPointAfter(newOp);
            }
        }
            }}
    }

     void registerInsertCombinationalNetworkHierarchyPass(){
        mlir::PassRegistration<InsertCombinationalNetworkHierarchy>(
            "insert-combinatorial-logic-hierarchy", 
            "Inserts combinatorial logic operations",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createInsertCombinationalNetworkHierarchyPass();});
    }

    std::unique_ptr<mlir::Pass> createInsertCombinationalNetworkHierarchyPass(){
	    return std::make_unique<InsertCombinationalNetworkHierarchy>();
	}

    /// A transformation pass that removes all CombLogicOp operations by copying all 
    /// instruction from inside the operation to after the operation.  
    void FlattenCombinationalNetworkHierarchy::runOnOperation(){
        //Get current module operation
        //secfir::FModuleOp module = getOperation();
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);

        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Define a list that will contain the existing combinational networks
        std::vector<mlir::Operation*> networks;
        //Go through all operations of the module
        for (auto &op : module.getBodyBlock()->getOperations()) {
            //We are only interessted in CombLogicOps
            if(secfir::isa<CombLogicOp>(op)){
                //Get the operation as SecFIR CombLogicOp
                secfir::CombLogicOp combOp = secfir::dyn_cast<secfir::CombLogicOp>(op);
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
                secfir::OutputCombOp outputOp = secfir::dyn_cast<secfir::OutputCombOp>(
                            combOp.getBodyBlock()->back());

                //Copy operations form inside the network to outside the network
                for(auto &innerOp : combOp.getBodyBlock()->getOperations()){
                    //Only move the operation if it is not an output operaton of the network
                    if(!secfir::isa<secfir::OutputCombOp>(innerOp)){
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
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createFlattenCombinationalNetworkHierarchyPass();});
    }

    std::unique_ptr<mlir::Pass> createFlattenCombinationalNetworkHierarchyPass(){
	    return std::make_unique<FlattenCombinationalNetworkHierarchy>();
	}
}
}