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
#include "Passes/IRTransformation.h"
#include "Util/util.h"



namespace circt{
namespace secfir{

using namespace circt;
using namespace secfir;


    /// Function that inserts registers to pipeline the input
    /// of a specified operation. Thereby, registers that already
    /// exist will we reused. Returns the number of inserted registers.
    ///
    /// builder             OpBuilder to create registers
    /// location            Location for new registers
    /// numberRegisters     Number of registers required for pipelining
    /// value               Input value that should be pipelined
    /// op                  Operation of the input
    /// clk                 Clock for the new registers
    /// registers           List that will contain the register used 
    ///                         for pipelining
    unsigned pipelineOperationInput(
        mlir::OpBuilder builder,
        mlir::Location location,
        unsigned numberRegisters,
        mlir::Value value,
        mlir::Operation &op,
        mlir::Value &clk,
        std::vector<Operation *> &registers
    ){
        //Save the current insertion point of the operation builder
        mlir::OpBuilder::InsertPoint insertPoint = builder.saveInsertionPoint();
        //Determine the point where registers need to be added, by 
        //searching for registers that can be reused
        mlir::Value startPoint = value;
        while(numberRegisters){
            bool exit = true;
            //Check all operations that uses this value for registers
            for(auto user: startPoint.getUsers()){
                if(isa<RegOp>(user)){
                    //Set start point for new registers 
                    startPoint = user->getResult(0);
                    //Add this register to the list of registers
                    registers.push_back(user);
                    //Reduce the number of required registers
                    numberRegisters--;
                    //Continue searching for reusable registers
                    exit = false;
                    //We can continue with the next value
                    break;
                }
            }
            //Exit search if no suitable register exists
            if(exit) break;
        }
        //Set the instertion point of the builder after the last
        //found register
        builder.setInsertionPointAfterValue(startPoint);
        //Initialize the number of inserted registers
        unsigned addedRegister = 0;
        //Add the required registers
        for(unsigned i=0; i<numberRegisters; i++){
            mlir::Value input;
            //The first input is the determined starting point
            //and all other inputs are defined by the previous register
            if(i == 0) input = startPoint;
            else input = registers[registers.size()-1]->getResult(0);
            //Create a new register
            RegOp newReg = builder.create<RegOp>(
                    location,
                    value.getType(),
                    input,
                    clk,
                    builder.getStringAttr("reg_pipeline"));
            //Increment number of inserted registers
            addedRegister++;
            //Add the new register to the list of registers
            registers.push_back(newReg);
        }
        //Replace the input of the specified operation
        //with the pipelined version        
        value.replaceUsesWithIf(
                registers[registers.size()-1]->getResult(0), 
                [&op](OpOperand &operand) {
                    return operand.getOwner() == &op;
                    });
        //Restore the original insertion point of the builder
        builder.restoreInsertionPoint(insertPoint);
        //Retrun the number of added registers
        return addedRegister;
    }

    /// Function that assigns each operation in a module to different
    /// combinational logic blocks, where the id of the logic block
    /// indicates the latency of the block. Returns the number of registers
    /// added for pipelining.
    ///
    /// operationList           List of operation to assign to combinational 
    ///                             logic blocks
    /// clk                     Clock for potential added registers
    /// builder                 OpBuilder for creating registers
    /// pipeline                If true additional registers will be added 
    ///                             for pipelining
    /// valueToNetworkMap       Datastructure that will be filled with the 
    ///                             mapping from values to logic block id
    /// inputNetworks           Datastructure that will be filled with 
    ///                             the inputs of each logic block
    /// operationsNetworks      Datastructure that will be filled with the
    ///                             operations assigned to each logic block
    /// outputNetworks          Datastructure that will be filled with the 
    ///                             outputs of each logic block
    /// outputRegisterNetworks  Datastructure that will be filled with the
    ///                             registers a logic block is connected to
    ///                             at the output side
    /// insertion points        Datastructure that will be filled with the
    ///                             insertion points for each logic block                       
    unsigned assignOperationToCombinationalNetwork(
        mlir::Block::OpListType &operationList,
        mlir::Value clk,
        mlir::OpBuilder builder,
        bool pipeline,
        mlir::DenseMap<mlir::Value, unsigned> &valueToNetworkMap,
        std::vector<std::vector<mlir::Value>> &inputNetworks,
        std::vector<std::vector<mlir::Operation*>> &operationNetworks,
        std::vector<std::vector<mlir::Value>> &outputNetworks,
        std::vector<std::vector<mlir::Operation*>> &outputRegisterNetworks,
        std::vector<mlir::OpBuilder::InsertPoint> &insertionPoints
    ){
        //Initialize the number of added registers
        unsigned addedRegister = 0;
        //Initialize the ID of the logic blocks
        unsigned networkId = 0;
        //Go to all operations in the list and assign the corresponding block ID
        for (auto &op : operationList) {
            //Handle register operations
            if(isa<RegOp>(op)){
                //Get the operation as register
                RegOp regOp = dyn_cast<RegOp>(op);
                //The network id of the register is one larger than of the input
                networkId = valueToNetworkMap[regOp.input()];
                valueToNetworkMap[regOp.getResult()] = networkId + 1;
                //Create new layer of input/output values and operations for 
                //a new combinational network if it does not already exist
                if(inputNetworks.size() < networkId+2){
                    inputNetworks.push_back(std::vector<mlir::Value>());
                    outputNetworks.push_back(std::vector<mlir::Value>());
                    operationNetworks.push_back(std::vector<mlir::Operation*>());
                    //outputRegisterNetworks.push_back(std::vector<mlir::Operation*>());
                    insertionPoints.push_back(builder.saveInsertionPoint());
                }
                if(outputRegisterNetworks.size() < networkId+1){
                    outputRegisterNetworks.push_back(std::vector<mlir::Operation*>());
                }
                //Add the register to the corresponding list of output register
                //Add input of register operation to the outputs of the current network 
                if(regOp.input().getDefiningOp()){ 
                        //Check that there was indeed a logic block
                        if(!isa<RegOp>(regOp.input().getDefiningOp())){
                            outputRegisterNetworks[networkId].push_back(regOp);
                            outputNetworks[networkId].push_back(regOp.input());
                        }
                    //Set insertion point for network
                    builder.setInsertionPointAfterValue(regOp.input());
                    insertionPoints[networkId] = builder.saveInsertionPoint();
                }
                //Add output of register operation to the inputs of the next network
                for(auto user: regOp.getResult().getUsers()){
                    if(!isa<RegOp>(user)){
                        if(!secutil::vectorContainsValue(inputNetworks[networkId+1], regOp.getResult())){
                            inputNetworks[networkId+1].push_back(regOp.getResult());
                            break;
                        }
                    }
                }
                // for(mlir::Operation *user : regOp.getResult().getUsers()){
                //     if(user->getResults().size() == 1){
                //         if(valueToNetworkMap.count(user->getResults()[0])){
                //             // user->dump();
                //             inputNetworks[valueToNetworkMap[user->getResults()[0]]].push_back(regOp.getResult());
                //         }
                //     }
                // }
            //Handle Output operations
            } else if(isa<OutputOp>(op)){
                //Get the operation as an output operation
                OutputOp outputOp = dyn_cast<OutputOp>(op);
                //Set network ID to highest ID of inputs
                for(mlir::Value operand : outputOp.getOperands()){
                    if(valueToNetworkMap[operand] > networkId){
                        networkId = valueToNetworkMap[operand];
                    }
                    //Add the operands to the outputs of the corresponding networks
                    if(operand.getDefiningOp()){
                        outputNetworks[valueToNetworkMap[operand]].push_back(operand);
                    }
                }
                //Insert registers for pipelining when necessary
                for(mlir::Value operand : outputOp.getOperands()){
                    //Check whether new registers are required
                    if(valueToNetworkMap[operand] < networkId){
                        //Get the logic block ID of the operand
                        unsigned operandNetwork = valueToNetworkMap[operand];
                        if(pipeline){     
                            //Determin the number of required registers
                            unsigned diff = networkId - operandNetwork;
                            //Pipeline the operand
                            std::vector<mlir::Operation *> inputRegisters;
                            addedRegister += pipelineOperationInput(
                                        builder,
                                        op.getLoc(),
                                        diff,
                                        operand,
                                        op,
                                        clk,
                                        inputRegisters);
                            //Assign a logic block ID to the new registers
                            for(unsigned i=0; i<inputRegisters.size(); i++){
                                valueToNetworkMap[inputRegisters[i]->getResult(0)] = operandNetwork+i+1;
                            }
                            //Add the register to the corresponding list of output register
                            //Add input of register operation to the outputs of the current network 
                            if(operand.getDefiningOp()){
                                if(!secutil::vectorContainsOperation(outputRegisterNetworks[operandNetwork], inputRegisters[0])){
                                    outputRegisterNetworks[operandNetwork].push_back(inputRegisters[0]);
                                }
                                //Set insertion point for network
                                builder.setInsertionPointAfterValue(operand);
                                insertionPoints[operandNetwork] = builder.saveInsertionPoint();
                            }
                        }else{
                            if(operand.getDefiningOp() && 
                                    !secutil::vectorContainsValue(outputNetworks[operandNetwork], operand)){
                                outputNetworks[operandNetwork].push_back(operand);
                            }
                            if(!secutil::vectorContainsValue(inputNetworks[networkId], operand)){
                                inputNetworks[networkId].push_back(operand);
                            }
                        }
                    }
                }
            //Handle all other operations with a single result
            }else if(op.getNumResults() == 1){
                //Get the operands of that operation
                mlir::OperandRange opOperands = op.getOperands();
                //Set network ID to highest ID of inputs
                for(unsigned i=0; i<opOperands.size(); i++){
                    //Add input operand to input list of current network, if
                    //it is a module input and it is not already in the list
                    if(!opOperands[i].getDefiningOp()){ 
                        if(!secutil::vectorContainsValue(inputNetworks[0], opOperands[i])){
                            valueToNetworkMap[opOperands[i]] = 0;
                            inputNetworks[0].push_back(opOperands[i]);
                        }
                    } 
                    if(valueToNetworkMap[opOperands[i]] > networkId){
                        networkId = valueToNetworkMap[opOperands[i]];  
                    }
                }
                //Insert registers for pipelining when necessary
                for(mlir::Value operand : opOperands){
                    if(operand.getDefiningOp() && isa<ConstantOp>(operand.getDefiningOp())){
                        if(!secutil::vectorContainsValue(inputNetworks[networkId], operand)){
                            inputNetworks[networkId].push_back(operand);
                            //operationNetworks[networkId].push_back(operand.getDefiningOp());
                            valueToNetworkMap[operand] = networkId;
                        }
                    }
                    //Check if pipelining is necessary
                    if(valueToNetworkMap[operand] < networkId){
                        //Get logic block ID of the operand
                        unsigned operandNetwork = valueToNetworkMap[operand];
                        if(pipeline){
                            //Determin the number of new registers
                            unsigned diff = networkId - valueToNetworkMap[operand];
                            //Pipeline the operand
                            std::vector<mlir::Operation *> inputRegisters;
                            addedRegister += pipelineOperationInput(
                                        builder,
                                        op.getLoc(),
                                        diff,
                                        operand,
                                        op,
                                        clk,
                                        inputRegisters);
                            //Assign a logic block ID to the new registers
                            for(unsigned i=0; i<inputRegisters.size(); i++){
                                valueToNetworkMap[inputRegisters[i]->getResult(0)] = operandNetwork+i+1;
                            }
                            //Get a pointer to the result of the last register
                            mlir::Value lastRegisterOutput = inputRegisters[inputRegisters.size()-1]->getResult(0);
                            //Add the register to the corresponding list of output register
                            //Add input of register operation to the outputs of the current network 
                            if(operand.getDefiningOp()){
                                if(!secutil::vectorContainsOperation(outputRegisterNetworks[operandNetwork], inputRegisters[0])){
                                    outputRegisterNetworks[operandNetwork].push_back(inputRegisters[0]);
                                    outputNetworks[operandNetwork].push_back(operand);
                                }
                                //Set insertion point for network
                                builder.setInsertionPointAfterValue(operand);
                                insertionPoints[operandNetwork] = builder.saveInsertionPoint();
                            }
                            //Add output of register operation to the inputs of the next network
                            if(!secutil::vectorContainsValue(inputNetworks[networkId], lastRegisterOutput)){
                                inputNetworks[networkId].push_back(lastRegisterOutput); 
                            }
                        }else{
                            if(operand.getDefiningOp() && 
                                    !secutil::vectorContainsValue(outputNetworks[operandNetwork], operand)){
                                outputNetworks[operandNetwork].push_back(operand);
                            }
                            if(!secutil::vectorContainsValue(inputNetworks[networkId], operand)){
                                inputNetworks[networkId].push_back(operand);
                            }
                            
                        }
                    }
                }
                //Set the logic block ID of this operation
                valueToNetworkMap[op.getResult(0)] = networkId;
                //Add operation to the network with the correct ID
                if(!secutil::vectorContainsOperation(operationNetworks[networkId], &op))
                    operationNetworks[networkId].push_back(&op);                
            }
            //Reset network ID
            networkId = 0;
        }
        //Return the number of added registers
        return addedRegister;
    }

    /// Function that moves a list of operations inside a combinational logic
    /// block operation.
    ///
    /// builder             Operation builder for IR manipulation
    /// networkId           Index of current logic block
    /// logicBlock          CombLogicOp to move operation to
    /// operationsNetwork   Operations that should be moved
    /// definedValues       List of values that are defined within the
    ///                         logic block (must contain the inputs)
    /// blockValueMapping   Mapping from values outside of logic block
    ///                         to values inside of the logic block
    ///                         (must contain all defined values)
    /// outputsNetwork      List of external values that are outputs of 
    ///                         the logic block
    /// deleteOperations    List that will contain operations that are not 
    ///                         longer required (operations that are moved)
    /// outputLogicBlock    Datastructure that will contain the internal values 
    ///                         that are outputs of the logic block
    void moveOperationsInsideCombinationalLogic(
        mlir::OpBuilder builder,
        unsigned networkId,
        CombLogicOp &logicBlock,
        std::vector<mlir::Operation*> &operationsNetwork,
        std::vector<mlir::Value> &definedValues, 
        mlir::BlockAndValueMapping &blockValueMapping,
        std::vector<mlir::Value> &outputsNetwork,
        std::vector<mlir::Operation*> &deleteOperations,
        mlir::SmallVector<mlir::Value, 0> &outputLogicBlock,
        mlir::DenseMap<mlir::Value, mlir::Value> &outputNetworkMap
    ){       
        unsigned copyCount = 0;
        unsigned networkSize = operationsNetwork.size();
        while (copyCount < networkSize){                       
            for(unsigned opIndex=0; opIndex < operationsNetwork.size(); opIndex++){
                auto op = operationsNetwork[opIndex];
                if(op != NULL){
                    bool copy = true;
                    for(auto operand : op->getOperands()){
                        if(!secutil::vectorContainsValue(definedValues, operand)){
                            copy = false;
                            break;
                        }
                    }
                    //Do not copy constant operations
                    if(isa<ConstantOp>(op)){
                        copy = false;
                        networkSize--;
                        operationsNetwork[opIndex] = NULL;
                    }
                    if(copy && op->getResults().size() > 0){
                        copyCount++;
                        definedValues.push_back(op->getOpResult(0));
                        //Clone operation into the network
                        mlir::Operation *newOp = builder.clone(*op, blockValueMapping);
                        //If the result is an network output the usage of the result must be 
                        //changed to the output of the network
                        unsigned index = 0;
                        if(secutil::vectorContainsValue(outputsNetwork, op->getResult(0))){
                            //Get push result to the output vector and determine current index
                            index = outputLogicBlock.size();
                            outputLogicBlock.push_back(newOp->getResult(0));
                            //Determine usages of the result that are within the current network
                            SmallPtrSet<Operation *, 1> except;
                            for(mlir::Operation *use: op->getResult(0).getUsers()){
                                if(secutil::vectorContainsOperation(operationsNetwork, use))
                                        except.insert(use);
                            }
                            //Replace all usages of the result that are not within this network
                            op->getResult(0).replaceAllUsesExcept(logicBlock.getResult(index),
                                    except);
                            outputNetworkMap[op->getResult(0)] = logicBlock.getResult(index);
                        }
                        //Set instertion point of the builder behind the new operation
                        builder.setInsertionPointAfter(newOp);

                        deleteOperations.push_back(op);
                        operationsNetwork[opIndex] = NULL;
                    }
                }
            }
        }
    }

    /// Function that removes existing loops in the design
    /// by replacing the feedback with constant operations.
    ///
    /// builder             Operation builder for IR manipulation
    /// operationList       List of operations to analyse
    /// loopMap             Datastructure that will be filled with a
    ///                         mapping from feedback values to constant
    ///                         operations that will be used instead
    void removeLoops(
        mlir::OpBuilder builder,
        mlir::Block::OpListType &operationList,
        mlir::DenseMap<mlir::Value, mlir::Value> &loopMap
    ){
        auto dummyValue = builder.getBoolAttr(false);
        for (auto &op : operationList) {
            if(op.getResults().size() > 0){
               

                for(unsigned i=0; i<op.getOperands().size(); i++){
                    mlir::Value operand = op.getOperand(i);
                    if(operand.getDefiningOp() && 
                                op.isBeforeInBlock(operand.getDefiningOp())){
                        
                        if(!loopMap.count(operand)){
                            secfir::ConstantOp constOp = builder.create<secfir::ConstantOp>(
                                    operand.getDefiningOp()->getLoc(),
                                    operand.getType(),
                                    dummyValue);
                            loopMap[operand] = constOp.getResult();
                        }
                        op.eraseOperand(i);
                        op.insertOperands(i, loopMap[operand]);
                    }
                }
            }
        }
    }

}
}