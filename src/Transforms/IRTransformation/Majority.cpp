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
using namespace secfir;

    void eraseUselessOperationRecursive(
        mlir::Operation &op
    ){
        //Ensure that operation is indeed not used
        if(!op.getUsers().empty()){
            return;
        }
        //Get the inputs of the operation
        mlir::ValueRange inputs =  op.getOperands();
        op.erase();
        //Erase all operations that only are used
        //from this operation
        for(mlir::Value in : inputs){
            if(in.getUsers().empty() && in.getDefiningOp()){
                eraseUselessOperationRecursive(*in.getDefiningOp());
            }
        }
    }

    void insertMajorityModule(
        mlir::Location location,
        secutil::SortingNetwork &network,
         secfir::CircuitOp circuitOp,
        mlir::OpBuilder builder
    ){
        //Get current context
        mlir::MLIRContext *context = builder.getContext();
        //Get the number of input wires of the sorting network
        unsigned num_inputs = network.getNumberOfInputs();
        //Create a list of ports
        auto type = secfir::UIntType::get(context, 1);
        auto flipType = secfir::FlipType::get(type);
        secfir::SmallVector<secfir::ModulePortInfo, 4> ports;
        //List of input ports
        for(unsigned i=0; i<num_inputs; i++){
            ports.push_back({builder.getStringAttr("in_" + std::to_string(i)), type});
        }
        //Single result
        ports.push_back({builder.getStringAttr("res"), flipType});

        mlir::StringAttr moduleName =  builder.getStringAttr(
                            "Majority"+ std::to_string(num_inputs) +"_Module");
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Initialize the wires of the sorting network
        //to the inputs of the module
        std::vector<mlir::Value> wires(num_inputs);
        for(unsigned i=0; i<num_inputs; i++){
            wires[i] = module.getBodyBlock()->getArgument(i);
        }
        //Insert logic of the sorting network
        for(auto compare : network.getNetwork()){
            //Create AND path of sorting network
            AndPrimOp andOp = builder.create<AndPrimOp>(
                location,
                type,
                wires[compare.first],
                wires[compare.second]);
            //Create OR path of sorting network
            OrPrimOp orOp = builder.create<OrPrimOp>(
                location,
                type,
                wires[compare.first],
                wires[compare.second]);
            //Update entries of wires
            wires[compare.first] = andOp.getResult();
            wires[compare.second] = orOp.getResult();
        }
        //The median of the sorting network is the output
        mlir::SmallVector<mlir::Value, 1> outputValue;
        outputValue.push_back(wires[ceil(num_inputs/2)]);
        builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    outputValue);
        //Erase the original output operation
        module.getOutputOp()->erase();
        //Erase all operations that are not connected
        //to the output (those exist as we only use one
        //value from the sorting network)
        for(mlir::Value w : wires){
            if(w.getUsers().empty() && w.getDefiningOp()){
                eraseUselessOperationRecursive(*w.getDefiningOp());
            }
        }
        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }

    void MajorityToLogic::runOnOperation() {

        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());

        unsigned index_majority = 0;
        //Get current combinational logic operation
        CircuitOp circuit = getOperation();
        for(auto &m : circuit.getBody()->getOperations()){
            if(isa<ModuleOp>(m)){
                ModuleOp module = dyn_cast<ModuleOp>(m);
                std::vector<mlir::Operation*> deleteOperations;
                for (auto &op : module.getBodyBlock()->getOperations()) {                    
                    if(isa<MajorityPrimOp>(op)){
                        MajorityPrimOp maj = dyn_cast<MajorityPrimOp>(op);

                        unsigned num_input = maj.getOperands().size();
                        std::string moduleName = "Majority"+std::to_string(num_input)+"_Module";
                        //Check whether a majority module already exist
                        //and create one if not
                        if(!circuit.lookupSymbol(moduleName)){
                            //Parse sorting network from file
                            secutil::SortingNetwork network(parameterFilename);
                            assert(num_input == network.getNumberOfInputs() &&
                                        "Provided sorting network has wrong size!");
                            //Insert the majority module based on the sorting network
                            insertMajorityModule(
                                circuit.getLoc(),
                                network,
                                circuit,
                                builder
                            );
                        }
                        builder.setInsertionPointAfter(&op);
                        mlir::StringAttr instanceName = builder.getStringAttr(
                                        "_majority" + std::to_string(num_input) + 
                                        "_module_" + std::to_string(index_majority));
                        //Get the operands, results, and types of the operation 
                        mlir::ValueRange valRange(op.getOperands());
                        mlir::ValueRange resRange(op.getResults());
                        mlir::TypeRange typeRange(op.getResultTypes());
                        //Create the instance operation
                        secfir::InstanceOp instance = builder.create<secfir::InstanceOp>(
                                    op.getLoc(),
                                    typeRange,
                                    instanceName,
                                    builder.getSymbolRefAttr(moduleName),
                                    valRange);
                        //Replace all useages of the original result with the result
                        //of the module
                        maj.getResult().replaceAllUsesWith(instance.getResult(0));                     
                        deleteOperations.push_back(&op);
                        index_majority++;
                    }
                }
                for(unsigned i=0; i<deleteOperations.size(); i++){
                    deleteOperations[i]->erase();
                }
            }
        }
    }

     void registerMajorityToLogicPass(){
        mlir::PassRegistration<MajorityToLogic>(
            "maj-to-logic", 
            "Transforms all majority operation to digital logic",
            []() -> std::unique_ptr<mlir::Pass>{return createMajorityToLogicPass();});
    }

    std::unique_ptr<mlir::Pass> createMajorityToLogicPass(){
	    return std::make_unique<MajorityToLogic>();
	}

}
}