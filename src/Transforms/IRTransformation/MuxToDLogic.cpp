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

    void secfir::MuxToDLogic::runOnOperation() {

        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Get current combinational logic operation
        //secfir::CombLogicOp logicBlock = getOperation();
        secfir::CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(m)){
                secfir::ModuleOp module = secfir::dyn_cast<secfir::ModuleOp>(m);
                 for (auto &operation : module.getBodyBlock()->getOperations()) {
                     if(secfir::isa<secfir::CombLogicOp>(operation)){
                         secfir::CombLogicOp logicBlock = secfir::dyn_cast<secfir::CombLogicOp>(operation);


        std::vector<mlir::Operation*> deleteOperations;
            
        for (auto &op : logicBlock.getBodyBlock()->getOperations()) {
            if(secfir::isa<secfir::MuxPrimOp>(op)){
                secfir::MuxPrimOp muxOp = secfir::dyn_cast<secfir::MuxPrimOp>(op);
                builder.setInsertionPointAfter(muxOp);
                // MUX(sel, a, b) = OR(AND(high, sel), AND(low, NOT(sel)))
                auto not_sel = builder.create<secfir::NotPrimOp>(
                            muxOp.getLoc(),
                            muxOp.sel().getType(),
                            muxOp.sel());
                auto andOpHigh = builder.create<secfir::AndPrimOp>(
                            muxOp.getLoc(),
                            muxOp.getResult().getType(),
                            muxOp.high(),
                            muxOp.sel());
                auto andOpLow = builder.create<secfir::AndPrimOp>(
                            muxOp.getLoc(),
                            muxOp.getResult().getType(),
                            muxOp.low(),
                            not_sel.getResult());
                auto orOp = builder.create<secfir::OrPrimOp>(
                            muxOp.getLoc(),
                            muxOp.getResult().getType(),
                            andOpHigh.getResult(),
                            andOpLow.getResult());                
                //Use the result of the last not operation wherever the result of the 
                //original or operation is used
                muxOp.getResult().replaceAllUsesWith(orOp.getResult());
                //Mark original or operation for removal
                deleteOperations.push_back(&op);
            }else if(secfir::isa<secfir::NodeOp>(op)){
                //Remove node operation
                secfir::NodeOp node = secfir::dyn_cast<secfir::NodeOp>(op);
                node.result().replaceAllUsesWith(node.input());
                deleteOperations.push_back(&op);
            }
        }
            

        for(unsigned i=0; i<deleteOperations.size(); i++){
            deleteOperations[i]->erase();
        }
                     
        }}}}

    }

     void registerMuxToDLogicPass(){
        mlir::PassRegistration<MuxToDLogic>(
            "mux-to-logic", 
            "Transforms all mux to digital logic",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createMuxToDLogicPass();});
    }

    std::unique_ptr<mlir::Pass> createMuxToDLogicPass(){
	    return std::make_unique<MuxToDLogic>();
	}

}
}