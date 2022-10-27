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

#ifndef CIRCT_DIALECT_SECFIR_IR_TRANSFORMATION_H
#define CIRCT_DIALECT_SECFIR_IR_TRANSFORMATION_H

#include "mlir/Pass/Pass.h"
#include "mlir/IR/BlockAndValueMapping.h"

#include "SecFIR/Ops.h"
#include "Util/SortingNetwork.h"

#include <set>


namespace circt {
namespace secfir {

    ///------------------------------------------------------------------------
    /// ***** Pass Options *****
    ///
    /// * Option to replace all or only marked operations 
    ///------------------------------------------------------------------------

    // Option to replace all or only marked operations
    enum ReplaceMethod {
        all, marked
    };

    ///------------------------------------------------------------------------
    /// ***** Passes *****
    ///
    /// * Pass that replaces some operations with a corresponding module. 
    /// * Pass that inserts combinational logic blocks
    /// * Pass that flattens combinational logic blocks
    /// * Pass that transforms a design to an Xor-And-Inverter graph
    /// * Pass that inserts logic of majority gates
    ///------------------------------------------------------------------------

    /// *** Insert Module Pass ***
    ///
    /// A transformation pass that instantiates a module for all 
    /// or marked operations.    
    class InsertGateModule : public mlir::PassWrapper<
            InsertGateModule, 
            mlir::OperationPass<secfir::CircuitOp>
    > {
    public:
        //Constructors
        InsertGateModule() = default;
        InsertGateModule(
                const InsertGateModule& pass) {}
        //Pass options
        mlir::Pass::Option<ReplaceMethod> parameterReplaceMethod{
                *this, 
                "method", 
                llvm::cl::desc("Replace method"),
                llvm::cl::values(
                    clEnumVal(all, "All combinational gates are replaced"),
                    clEnumVal(marked, "Only marked gates are replaced")),
                llvm::cl::init(all)};
        //Pass execution
        void runOnOperation() override;			
    };
    //Register and create functions
    void registerInsertGateModulePass();
    std::unique_ptr<mlir::Pass> createInsertGateModulePass();

    /// *** Insert Combinational Logic Hierarchy ***
    ///
    /// Pass that inserts the additional hierarchy of combinational logic block
    /// seperating combinational logic from registers.
    class InsertCombinationalNetworkHierarchy : public mlir::PassWrapper<
            InsertCombinationalNetworkHierarchy, 
            mlir::OperationPass<secfir::CircuitOp>
    > {
    public:
        //Constructors
        InsertCombinationalNetworkHierarchy() = default;
        InsertCombinationalNetworkHierarchy(
                const InsertCombinationalNetworkHierarchy& pass) {}
        //Pass options
        mlir::Pass::Option<bool> parameterNoPipeline{
                *this, 
                "no-pipeline", 
                llvm::cl::desc("Insert registers for pipelining"),
                llvm::cl::init(false),
                llvm::cl::value_desc("bool")};        
        //Define statistics
        mlir::Pass::Statistic insertedRegisterStatistic{this, 
                    "added registers", "The number of inserted registers for pipelining"};
        mlir::Pass::Statistic registerLayersStatistic{this,
                    "cycles", "The number of register layers, i.e., latency (last module)"};
        mlir::Pass::Statistic combLogicLayersStatistic{this,
                    "logic blocks", "The number of logic block layers (last module)"};
        //Pass execution
        void runOnOperation() override;			
    };
    //Register and create functions
    void registerInsertCombinationalNetworkHierarchyPass();
    std::unique_ptr<mlir::Pass> createInsertCombinationalNetworkHierarchyPass();

    /// *** Flatten Combinational Logic Hierarchy ***
    ///
    /// Pass that removes all CombLogicOp operations by copying all 
    /// instruction from inside the operation to after the operation. 
    class FlattenCombinationalNetworkHierarchy : public mlir::PassWrapper<
            FlattenCombinationalNetworkHierarchy, 
            mlir::OperationPass<secfir::CircuitOp>
    > {
    public:
        //Constructors
        FlattenCombinationalNetworkHierarchy() = default;
        FlattenCombinationalNetworkHierarchy(
                const FlattenCombinationalNetworkHierarchy& pass) {}
        //Pass execution
        void runOnOperation() override;			
    };
    //Register and create functions
    void registerFlattenCombinationalNetworkHierarchyPass();
    std::unique_ptr<mlir::Pass> createFlattenCombinationalNetworkHierarchyPass();

    /// *** To XAG Pass ***
    ///
    /// A transformation pass to Xor-And-Inverter graph
    class ToXAG : public mlir::PassWrapper<
            ToXAG, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        ToXAG() = default;
        ToXAG(const ToXAG& pass){}
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerToXAGPass();
    std::unique_ptr<mlir::Pass> createToXAGPass();

    /// *** Majority to Digital Logic Pass ***
    ///
    /// A transformation pass that inserts digital logic 
    /// instead of a majority operation
    class MajorityToLogic : public mlir::PassWrapper<
            MajorityToLogic, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        MajorityToLogic() = default;
        MajorityToLogic(const MajorityToLogic& pass){}
        //Pass options
        mlir::Pass::Option<std::string> parameterFilename{
					*this, 
					"sortNet", 
					llvm::cl::desc("File with sorting network description"),
					llvm::cl::init(""),
					llvm::cl::value_desc("filename")};
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerMajorityToLogicPass();
    std::unique_ptr<mlir::Pass> createMajorityToLogicPass();

    /// *** Mux to Digital Logic Pass ***
    ///
    /// A transformation pass that inserts digital logic
    /// instead of a MUX operation
    class MuxToDLogic : public mlir::PassWrapper<
            MuxToDLogic, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        MuxToDLogic() = default;
        MuxToDLogic(const MuxToDLogic& pass){}
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerMuxToDLogicPass();
    std::unique_ptr<mlir::Pass> createMuxToDLogicPass();

    /// *** Pipelining Pass ***
    ///
    /// Transformation pass that inserts registers 
    /// where necessary for pipelining the design
    class PipeliningPass : public mlir::PassWrapper<
            PipeliningPass, 
            mlir::OperationPass<secfir::CircuitOp>
    > {
    public:
        //Constructors
        PipeliningPass() = default;
        PipeliningPass(const PipeliningPass& pass) {}
        //Pass execution
        void runOnOperation() override;			
    };
    //Register and create functions
    void registerPipeliningPass();
    std::unique_ptr<mlir::Pass> createPipeliningPass();



    ///------------------------------------------------------------------------
    /// ***** Insert Module *****
    ///
    /// * Functions that inserts module containing a single operation. 
    /// * Functions that replace an operation with a corresponding module. 
    ///------------------------------------------------------------------------

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
    );

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
    );

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
    );

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
    );

    ///------------------------------------------------------------------------
    /// ***** Combinational Logic *****
    ///
    /// * Functions that inserts register for pipelining. 
    /// * Function that assigns operations to combinational logic blocks. 
    /// * Function that removes loops from a module
    ///------------------------------------------------------------------------

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
        std::vector<secfir::Operation *> &registers
    );

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
    );

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
    );

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
    );
}
}

#endif // !CIRCT_DIALECT_SECFIR_IR_TRANSFORMATION_H