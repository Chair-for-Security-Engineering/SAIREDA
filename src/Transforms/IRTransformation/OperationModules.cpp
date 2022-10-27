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

namespace circt{
namespace secfir{

using namespace circt;

    /// Function that inserts a module containing a single 
    /// register to the begining of a provided circuit.
    ///
    /// location            Location of the to insert module
    /// op                  Register as mlir operation
    /// moduleName          The name the new module should get
    /// circuitOP           The circuit the module should be inserted
    /// builder             An operation builder for IR creation
    /// context             The current context
    void insertRegisterModule(
        mlir::Location location,
        mlir::Operation &op,
        mlir::StringAttr moduleName,
        secfir::CircuitOp circuitOp,
        mlir::OpBuilder builder,
        mlir::MLIRContext *context
    ){
        //Assure that input is a register operation
        assert(secfir::isa<secfir::RegOp>(op) && "Operation is not a register!");
        //Create a list of ports
        auto type = secfir::UIntType::get(context, 1);
        auto clockType = secfir::ClockType::get(context);
        auto flipType = secfir::FlipType::get(type);
        secfir::SmallVector<secfir::ModulePortInfo, 2> ports;
        ports.push_back({builder.getStringAttr("in"), type});
        ports.push_back({builder.getStringAttr("clk"), clockType});
        ports.push_back({builder.getStringAttr("res"), flipType});
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Get a mapping from the inputs of the operation 
        //to the inputs of the module
        mlir::BlockAndValueMapping blockValueMapping;
        blockValueMapping.map(op.getOperand(0), 
                            module.getBodyBlock()->getArgument(0));
        blockValueMapping.map(op.getOperand(1), 
                            module.getBodyBlock()->getArgument(1));
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Clone the operation within the module
        mlir::Operation *newOp = builder.clone(op, blockValueMapping);
        //Create an output operation that connects the cloned operation
        //to the output
        mlir::SmallVector<mlir::Value, 1> outputValue;
        outputValue.push_back(newOp->getResult(0));
        builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    outputValue);
        //Erase the original output operation
        module.getOutputOp()->erase();
        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }


    /// Function that inserts a module containing a single 
    /// uniary operation to the begining of a provided circuit.
    ///
    /// location            Location of the to insert module
    /// op                  The uniary operation
    /// moduleName          The name the new module should get
    /// circuitOP           The circuit the module should be inserted
    /// builder             An operation builder for IR creation
    /// context             The current context
    void insertUnaryModule(
        mlir::Location location,
        mlir::Operation &op,
        mlir::StringAttr moduleName,
        secfir::CircuitOp circuitOp,
        mlir::OpBuilder builder,
        mlir::MLIRContext *context
    ){
        //Assure an unary operation
        assert(op.getOperands().size() == 1 && "Operation is not unary!");
        //Create a list of ports
        auto type = secfir::UIntType::get(context, 1);
        auto flipType = secfir::FlipType::get(type);
        secfir::SmallVector<secfir::ModulePortInfo, 2> ports;
        ports.push_back({builder.getStringAttr("in"), type});
        ports.push_back({builder.getStringAttr("res"), flipType});
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Get a mapping from the inputs of the operation 
        //to the inputs of the module
        mlir::BlockAndValueMapping blockValueMapping;
        blockValueMapping.map(op.getOperand(0), 
                            module.getBodyBlock()->getArgument(0));
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Clone the operation within the module
        mlir::Operation *newOp = builder.clone(op, blockValueMapping);
        //Create an output operation that connects the cloned operation
        //to the output
        mlir::SmallVector<mlir::Value, 1> outputValue;
        outputValue.push_back(newOp->getResult(0));
        builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    outputValue);
        //Erase the original output operation
        module.getOutputOp()->erase();
        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }

    /// Function that inserts a module containing a single 
    /// binary operation to the begining of a provided circuit.
    ///
    /// location            Location of the to insert module
    /// op                  The binary operation
    /// moduleName          The name the new module should get
    /// circuitOP           The circuit the module should be inserted
    /// builder             An operation builder for IR creation
    /// context             The current context
    void insertBinaryModule(
        mlir::Location location,
        mlir::Operation &op,
        mlir::StringAttr moduleName,
        secfir::CircuitOp circuitOp,
        mlir::OpBuilder builder,
        mlir::MLIRContext *context
    ){
        //Assure an binary operation
        assert(op.getOperands().size() == 2 && "Operation is not binary!");
        //Create a list of ports
        auto type = secfir::UIntType::get(context, 1);
        auto flipType = secfir::FlipType::get(type);
        secfir::SmallVector<secfir::ModulePortInfo, 3> ports;
        ports.push_back({builder.getStringAttr("lhs"), type});
        ports.push_back({builder.getStringAttr("rhs"), type});
        ports.push_back({builder.getStringAttr("res"), flipType});
        //Insert the new module to the beginning of the circuit
        auto savedInsertionPointer = builder.saveInsertionPoint();
        builder.setInsertionPointToStart(circuitOp.getBody());
        secfir::ModuleOp module = builder.create<secfir::ModuleOp>(
                    location,
                    moduleName,
                    ports);
        //Get a mapping from the inputs of the operation 
        //to the inputs of the module
        mlir::BlockAndValueMapping blockValueMapping;
        blockValueMapping.map(op.getOperand(0), 
                            module.getBodyBlock()->getArgument(0));
        blockValueMapping.map(op.getOperand(1), 
                            module.getBodyBlock()->getArgument(1));
        //Set the insertion pointer to the begin of the module
        builder.setInsertionPointToStart(module.getBodyBlock());
        //Clone the operation within the module
        mlir::Operation *newOp = builder.clone(op, blockValueMapping);
        //Create an output operation that connects the cloned operation
        //to the output
        mlir::SmallVector<mlir::Value, 1> outputValue;
        outputValue.push_back(newOp->getResult(0));
        builder.create<secfir::OutputOp>(
                    module.getLoc(),
                    outputValue);
        //Erase the original output operation
        module.getOutputOp()->erase();
        //Recover original insertion point
        builder.restoreInsertionPoint(savedInsertionPointer);
    }

    /// Function that replaces an operation with a module
    /// that has a single result. The original operation is 
    /// not erased but the result is not used any more
    /// (to ensure that loops outside this function work properly).
    ///
    /// op              Operation that is replaced
    /// instanceName    The name the instance should be given
    /// moduleName      The name of the module
    /// builder         An operation builder for IR manipulation    
    void insertInstanceOfOperationModule(
        mlir::Operation &op,
        mlir::StringAttr instanceName,
        mlir::FlatSymbolRefAttr moduleName,
        mlir::OpBuilder builder
    ){
        //Get the operands, results, and types of the operation 
        mlir::ValueRange valRange(op.getOperands());
        mlir::ValueRange resRange(op.getResults());
        mlir::TypeRange typeRange(op.getResultTypes());
        //Create the instance operation
        secfir::InstanceOp instance = builder.create<secfir::InstanceOp>(
                    op.getLoc(),
                    typeRange,
                    instanceName,
                    moduleName,
                    valRange);
        //Replace all useages of the original result with the result
        //of the module
        op.getResult(0).replaceAllUsesWith(instance.getResult(0));
    }

}
}