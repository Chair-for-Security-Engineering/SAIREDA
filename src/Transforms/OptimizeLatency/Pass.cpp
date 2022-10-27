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
#include "Passes/OptimizeLatency.h"


namespace circt{
namespace secfir{

using namespace circt; 
using namespace secfir;

///------------------------------------------------------------------------
/// *** Optimize Asynchon Gadget Pass ***
///
/// Transformation pass that switches the order of inputs
/// for gadgets with asynchon latency, such that the lhs input 
/// is dependent on less gadgets.
///------------------------------------------------------------------------
void OptimizeAsynchonGadgetLatencyPass::runOnOperation() {
    //Get a builder vor IR manipulation
    mlir::OpBuilder builder(&getContext());
    //Get current module operation
    secfir::CircuitOp circuit = getOperation();
    for(auto &module : circuit.getBody()->getOperations()){
    if(secfir::isa<secfir::ModuleOp>(module)){
    secfir::ModuleOp m = secfir::dyn_cast<secfir::ModuleOp>(module);
    //Go through all combinatorial logic blocks withing this module
    for (auto &op : m.getBodyBlock()->getOperations()) {
    if(secfir::isa<secfir::CombLogicOp>(op)){
        secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(op);
        //Define a map from values to the number of gadgets on the path to them
        mlir::DenseMap<mlir::Value, unsigned> gadgetsOnPath; 
        //Set the number of gadgets on the path of inputs to zero
        for(mlir::Value input: logicBlock.getBodyBlock()->getArguments()){
            gadgetsOnPath[input] = 0;
        }
        //Go through all operation in the logic block
        for (auto &op : logicBlock.getBodyBlock()->getOperations()) {
            //Only look at operations with one result
            if(op.getResults().size() == 1){
                gadgetsOnPath[op.getResult(0)] = 0;
                //Determine maximum of gadgets on input pathes
                for(mlir::Value input: op.getOperands()){
                    if(gadgetsOnPath[op.getResult(0)] < gadgetsOnPath[input]){
                        gadgetsOnPath[op.getResult(0)] = gadgetsOnPath[input];
                    }
                }
                //Increase number of gadgets on the path for the
                //result if the operation itself is a gadget
                if(op.hasTrait<mlir::OpTrait::SCAGadget>()){
                    gadgetsOnPath[op.getResult(0)]++;
                }
                //Switch inputs for gadgets with asynchon latency
                //if beneficial
                if(isa<PiniAndGadgetOp>(op) ||
                        isa<CiniAndGadgetOp>(op) ||
                        isa<IciniAndGadgetOp>(op)){
                    //Get both inputs
                    mlir::Value lhs = op.getOperand(0);
                    mlir::Value rhs = op.getOperand(1);
                    //Switch if on path to rhs are more gadgets
                    //than on path to lhs
                    if(gadgetsOnPath[lhs] < gadgetsOnPath[rhs]){
                        op.setOperand(0, rhs);
                        op.setOperand(1, lhs);
                        //Increase number of performed switches
                        switchStatistic++;
                    }
                }

            }

        }

    }
    }
    }
    }
}

void registerOptimizeAsynchonGadgetLatencyPass(){
    mlir::PassRegistration<OptimizeAsynchonGadgetLatencyPass>(
        "opt-gadget-latency", 
        "Switch gadget inputs if better for latency",
        []() -> std::unique_ptr<mlir::Pass>{return secfir::createOptimizeAsynchonGadgetLatencyPass();});
}

std::unique_ptr<mlir::Pass> createOptimizeAsynchonGadgetLatencyPass(){
    return std::make_unique<OptimizeAsynchonGadgetLatencyPass>();
}


}
}