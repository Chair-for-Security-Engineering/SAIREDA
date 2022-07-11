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
#include "Passes/OptimizationPasses.h"

#include "mlir/Transforms/GreedyPatternRewriteDriver.h"

#include "Util/util.h"

namespace circt{
namespace secfir{

using namespace circt;

    /// An optimization pass that goes though all operations of 
    /// a module and removes all NodeOp operations, by replacing 
    /// all usages with the corresponding input.
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
}
}