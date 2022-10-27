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

namespace circt{
namespace secfir{

using namespace circt;

    //Definition of a map{operand, latency}
    //mlir::DenseMap<mlir::Value, unsigned> latencyMap;
    //Numbers of registers that use the operand
    int numRegChecked;

    //Function to find the latency of an added operand
    int getLatencyOp(
            mlir::Value op,
            mlir::DenseMap<mlir::Value, unsigned> &latencyMap
    ){
        int foundLatency = 0;
        foundLatency = latencyMap.find(op)->second;
        return(foundLatency);
    }
    
    //Function to add a register when the latencies are not equal.
    void addRegister(
            mlir::Value clock, 
            mlir::Value operand, 
            mlir::Operation* op, 
            int numReg, 
            int index, 
            mlir::OpBuilder opBuilder,
            mlir::DenseMap<mlir::Value, unsigned> &latencyMap
    ){
        //Sets the place to be added to the register        
        opBuilder.setInsertionPointAfter(op->getPrevNode());
        auto regOp = opBuilder.create<secfir::RegOp>(
                    operand.getLoc(),
                    operand.getType(),
                    operand,
                    clock,
                    opBuilder.getStringAttr("Reg" + std::to_string(0)));
        //set the register as the new operand
        op->setOperand(index, regOp);
        latencyMap[regOp.getResult()] = getLatencyOp(operand, latencyMap)+1;
        //For more register the function calls itself
        if(numReg>1){
            addRegister(clock, regOp, op, numReg-1, index, opBuilder, latencyMap);
        }
    }
    
    //Utilizes the registers connected to the same operand
    void checkReg(mlir::Value operand, mlir::Operation* op, int numChecks, int index){
        for(auto use: operand.getUsers()){
            if(secfir::isa<secfir::RegOp>(use) && numChecks != 0){
                numRegChecked++;
                op->setOperand(index, use->getResult(0));
                checkReg(use->getResult(0), op, numChecks-1, index);
            }
        }
    }  

    void secfir::PipeliningPass::runOnOperation() {
        //Get a clock for the register
        mlir::Value clock;
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        mlir::DenseMap<mlir::Value, unsigned> latencyMap;
        //Get current combinational logic operation
        //secfir::CombLogicOp logicBlock = getOperation();
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                //Get the arguments, get the clock and set the latencies to null for each input.
                for(auto &op : module.getBodyBlock()->getArguments()){
                    if(op.getType().isa<secfir::ClockType>()){
                        clock = op;
                    }
                    else {
                    //if(op.getType().isa<secfir::UIntType>()){
                        latencyMap[op] = 0;
                    }
                }
                
                //Get the operations and difference between registers and other operations
                for(auto &op : module.getBodyBlock()->getOperations()){
                    if(secfir::isa<secfir::RegOp>(op)){
                        //Register have a latency of latencyOperand +1
                        //latencyMap[op.getResult(0)] = getLatencyOp(op.getOperand(0), latencyMap)+1;
                        latencyMap[op.getResult(0)] = latencyMap[op.getOperand(0)];
                    }else{
                        std::vector<int> tempLatencyOp = {};
                        //Get the operands of each operation and its latency
                        for(mlir::Value operand:op.getOperands()){
                            //if(operand.getDefiningOp() || operand.getType().isa<secfir::UIntType>()){
                            if(!operand.getType().isa<secfir::ClockType>()){
                                tempLatencyOp.push_back(getLatencyOp(operand, latencyMap));
                            }
                        }
                        
                        //Get the max and min latency of each operand.
                        int maxtempLatencyOp = *std::max_element(tempLatencyOp.begin(),tempLatencyOp.end());
                        int mintempLatencyOp = *std::min_element(tempLatencyOp.begin(),tempLatencyOp.end());
                        if(!secfir::isa<secfir::OutputOp>(op)){
                            latencyMap[op.getResult(0)]  = maxtempLatencyOp;
                        }                        
                        //when maximum and minimum are not equal adds a register in the respective operand
                        if(maxtempLatencyOp!=mintempLatencyOp){
                            numRegChecked = 0;
                            int index = std::find(tempLatencyOp.begin(), tempLatencyOp.end(), mintempLatencyOp) - tempLatencyOp.begin();                            
                            checkReg(op.getOperand(index), &op, maxtempLatencyOp-mintempLatencyOp, index);
                            if(maxtempLatencyOp-mintempLatencyOp-numRegChecked !=0){
                                addRegister(clock, op.getOperand(index), &op, maxtempLatencyOp-mintempLatencyOp-numRegChecked, index, builder, latencyMap);
                            }
                        }
                    }
                }          
        }}

    }

     void registerPipeliningPass(){
        mlir::PassRegistration<PipeliningPass>(
            "pipeline", 
            "Pass for pipelining",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createPipeliningPass();});
    }

    std::unique_ptr<mlir::Pass> createPipeliningPass(){
	    return std::make_unique<PipeliningPass>();
	}

}
}