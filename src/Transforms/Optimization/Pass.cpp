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
#include "Passes/OptimizationPasses.h"


namespace circt{
namespace secfir{

using namespace circt;
using namespace secfir;

    ///------------------------------------------------------------------------
    /// ***** Remove Double-Not Pass *****
    ///
    /// Pass that goes though all modules an removes all double NOT operations,
    /// i.e. NOT(NOT()).
    ///------------------------------------------------------------------------
    void RemoveDoubleNotOpPass::runOnOperation() {
        //Get current module operation
        CircuitOp circuit = getOperation();
        for(auto &module : circuit.getBody()->getOperations()){
            if(isa<ModuleOp>(module)){
                ModuleOp m = dyn_cast<ModuleOp>(module);
        
        //Create a vector to store operations to delete
        std::vector<mlir::Operation*> deleteOperations;
        //Check all operations within the region for potential doubles
        for (auto &op : m.getBodyBlock()->getOperations()) {
            //Only consider NOT operations
            if(isa<NotPrimOp>(op)){
                NotPrimOp notOp = dyn_cast<NotPrimOp>(op);
                //Check whether there is a defining operation of the input
                if(notOp.input().getDefiningOp()){
                    mlir::Operation *inputOp = notOp.input().getDefiningOp();
                    //Check whether input comes from a NOT operation
                    if(isa<NotPrimOp>(inputOp)){
                        NotPrimOp notOp_in = dyn_cast<NotPrimOp>(inputOp);
                        //Replace all usages with the input of the first
                        //NOT operation
                        notOp.getResult().replaceAllUsesWith(notOp_in.input());
                        //Mark NOT operations for removal
                        deleteOperations.push_back(notOp);
                        if(notOp_in.getResult().getUseList()->hasOneUse()){
                            deleteOperations.push_back(notOp_in);
                        }
                    }
                }
            }
        }
        //Delete all marked node operations
        //Necessary to do at the end to keep all references correct
        for(unsigned i=0; i<deleteOperations.size(); i++){
            deleteOperations[i]->erase();
        }

    }
    }
    }
    
    void registerRemoveDoubleNotOpPass(){
        mlir::PassRegistration<RemoveDoubleNotOpPass>(
            "opt-not", 
            "Removes all redundantend not operations",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createRemoveDoubleNotOpPass();});
    }

    std::unique_ptr<mlir::Pass> createRemoveDoubleNotOpPass(){
	    return std::make_unique<RemoveDoubleNotOpPass>();
	}

    ///------------------------------------------------------------------------
    /// ***** Remove Node-Operations Pass *****
    ///
    /// An optimization pass that goes though all operations of 
    /// a module and removes all NodeOp operations, by replacing 
    /// all usages with the corresponding input.
    ///------------------------------------------------------------------------
    void secfir::RemoveNodeOpPass::runOnOperation() {
        //Get module operation
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                //Create a vector to store operations to delete
                std::vector<mlir::Operation*> deleteOperations;
                //Go through all operations in the module and find node operations
                for(auto &op : module.getBodyBlock()->getOperations()){
                    if(secfir::isa<secfir::NodeOp>(op)){
                        //Get an instanace of a node operation
                        secfir::NodeOp nodeOp = secfir::dyn_cast<secfir::NodeOp>(op);
                        //Replace all usages of the node operation with the input
                        //of the node operations
                        nodeOp.getResult().replaceAllUsesWith(nodeOp.input());
                        //Mark node operation for deletion
                        deleteOperations.push_back(nodeOp);
                    }
                }
                //Delete all marked node operations
                //Necessary to do at the end to keep all references correct
                for(unsigned i=0; i<deleteOperations.size(); i++){
                    deleteOperations[i]->erase();
                }
                //Ensure correct order of operations, may need multiple goes
                bool c = true;
                while(c){
                    c = false;
                    //Go through all operations
                    for(auto &op : module.getBodyBlock()->getOperations()){
                        //Check that all operands are defined before this operation
                        //and move operation if not (only exception are registers)
                        for(auto operand: op.getOperands()){
                            if(auto defOp = operand.getDefiningOp()){
                                if(op.isBeforeInBlock(defOp) && !isa<RegOp>(defOp)){
                                    op.moveAfter(defOp);
                                    c = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

     void registerRemoveNodeOpPass(){
        mlir::PassRegistration<RemoveNodeOpPass>(
            "remove-node-ops", 
            "Pass that removes node operations",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createRemoveNodeOpPass();});
    }

    std::unique_ptr<mlir::Pass> createRemoveNodeOpPass(){
	    return std::make_unique<RemoveNodeOpPass>();
	}

    ///------------------------------------------------------------------------
    /// ***** Remove Node-Operations Pass *****
    ///
    /// An optimization pass that goes though a modules and removes all
    /// redundant operations by replacing them with the result of the first
    /// of the redundant operations.
    ///
	/// Can violate security properties with respect to redundancy (FIA).
    ///------------------------------------------------------------------------
    void secfir::ReplaceRedundantOperations::runOnOperation() {
        //Get current module operation
        //secfir::FModuleOp m = getOperation();
        secfir::CircuitOp circuit = getOperation();
        for(auto &module : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(module)){
                secfir::ModuleOp m = secfir::dyn_cast<secfir::ModuleOp>(module);

        //Check all operations within the region for potential doubles
        for (auto &op : m.getBodyBlock()->getOperations()) {
            //Get type/name of operation
            mlir::OperationName opName = op.getName();
            //Get list of operands of operation
            mlir::OperandRange opOperands = op.getOperands();
            //Check whether operation has a result. If not there is nothing to do.
            mlir::Value opResult;
            if(op.getNumResults() == 1){
                //Do not replace register operations
                if(secfir::isa<secfir::RegOp>(op) ||
                   secfir::isa<secfir::RegInitOp>(op)){
                       continue;
                }
                //Get the result of the operation
                opResult = op.getResult(0);
                //Go through all remaining operations of the region 
                //and replace all with the same meaning
                mlir::Operation *compareOp = op.getNextNode();
                while(compareOp != nullptr){
                    //Temporal storage of next operation
                    mlir::Operation *compareOpTemp = compareOp->getNextNode();
                    bool replace = true;
                    //Check for the same operation type
                    if(compareOp->getName() == opName){
                        //Check for same openands
                        for(unsigned i=0; i<opOperands.size(); i++){
                            if(opOperands[i] != compareOp->getOperands()[i])
                                replace = false;
                        }
                    }else 
                        replace = false;
                    //Replace operation with same meaning
                    if(replace){
                        compareOp->getResult(0).replaceAllUsesWith(opResult);
                        compareOp->erase();
                        removedOpsStatistic++;
                    }
                    //Go to next operation
                    compareOp = compareOpTemp;
                }
            }               
        }
            }
        }
    }

    void registerReplaceRedundantOperationsPass(){
        mlir::PassRegistration<ReplaceRedundantOperations>(
            "opt-redundant-operations", 
            "Removes all redundantend operations",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createReplaceRedundantOperationsPass();});
    }

    std::unique_ptr<mlir::Pass> createReplaceRedundantOperationsPass(){
	    return std::make_unique<ReplaceRedundantOperations>();
	}
}
}
