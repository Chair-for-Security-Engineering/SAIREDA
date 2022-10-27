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

#ifndef CIRCT_DIALECT_SECFIR_TIGHTPROVER_H
#define CIRCT_DIALECT_SECFIR_TIGHTPROVER_H

#include "SecFIR/Ops.h"

#include "mlir/Pass/Pass.h"
#include "mlir/IR/Builders.h"

namespace circt {
namespace secfir {

    ///------------------------------------------------------------------------
    /// ***** Pass Options *****
    ///
    /// * Selection of masking method 
    ///------------------------------------------------------------------------

    /// Enum for selection of masking method 
    enum MaskingMethod {
        none, 
        pini, 
        doubleSni, 
        spini, 
        cini, 
        icini, 
        sni, 
        ni, 
        probSec, 
        probSecNoTightProve
    };
    /// Enum for selection of gadget type 
    enum GadgetType {
        hpc1, 
        hpc2
    };

    ///------------------------------------------------------------------------
    /// ***** Passes *****
    ///
    /// * Pass that inserts gadget operations 
    /// * Pass that inserts the logic of gadgets and duplication
    ///------------------------------------------------------------------------

    //// ***** Insert Gadget Pass *****
    ///
    /// Transformation pass that replaces every AND gate with a 
    /// side-channel secure gadget and inserts required refresh 
    /// gadgets.
    class InsertGadgetsPass : public mlir::PassWrapper<
            InsertGadgetsPass, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        InsertGadgetsPass() = default;
        InsertGadgetsPass(const InsertGadgetsPass& pass){}
        //Pass options
        mlir::Pass::Option<MaskingMethod> parameterMaskingType{
                *this, 
                "masking", 
                llvm::cl::desc("Masking method"),
                llvm::cl::values(
                    clEnumVal(none, "No masking"),
                    clEnumVal(sni, "Masking with SNI gadgets"),
                    clEnumVal(pini, "Masking with PINI gadgets"),
                    clEnumVal(spini, "Masking with gadgets that are both SNI and PINI"),
                    clEnumVal(cini, "Masking with CINI gadgets"),
                    clEnumVal(icini, "Masking with ICINI gadgets"),
                    clEnumVal(doubleSni, "Masking with double-SNI gatgets"),
                    clEnumVal(ni, "Masking with SNI gatgets, where the result is NI secure"),
                    clEnumVal(probSec, 
                            "Masking with SNI gatgets, where the result is probing secure"),
                    clEnumVal(probSecNoTightProve, 
                            "Masking with SNI AND gadgets, should only be used when known that the result is probing secure!")),
                llvm::cl::init(none)};
        //Pass statistics
        mlir::Pass::Statistic refSniGadgetsStatistic{this, 
                    "SNI refresh gadgets", 
                    "The number of inserted SNI refresh gadgets"};
        mlir::Pass::Statistic mulSniGadgetsStatistic{this, 
                    "SNI multiplication gadgets", 
                    "The number of inserted SNI multiplication gadgets"};
        mlir::Pass::Statistic piniGadgetsStatistic{this, 
                    "PINI multiplication gadgets", 
                    "The number of inserted PINI multiplication gadgets"};
        mlir::Pass::Statistic spiniGadgetsStatistic{this, 
                    "SPINI multiplication gadgets", 
                    "The number of inserted SPINI multiplication gadgets"};
        mlir::Pass::Statistic ciniGadgetsStatistic{this, 
                    "CINI multiplication gadgets", 
                    "The number of inserted CINI multiplication gadgets"};
        mlir::Pass::Statistic iciniGadgetsStatistic{this, 
                    "ICINI multiplication gadgets", 
                    "The number of inserted ICINI multiplication gadgets"};
        mlir::Pass::Statistic secureBlockStatistic{this, 
                    "secure blocks", 
                    "The number of secure combinatorial logic blocks"};
        mlir::Pass::Statistic overallStatistic{this, 
                    "overall blocks", 
                    "The number of insecure combinatorial logic blocks"};
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerInsertGadgetsPass();
    std::unique_ptr<mlir::Pass> createInsertGadgetsPass();


    //// ***** Define Gadget Type Pass *****
    ///
    /// Pass that allows to define the type of a gadget,
    /// by adding an annotation to the according operation.
    class DefineGadgetTypePass : public mlir::PassWrapper<
            DefineGadgetTypePass, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        DefineGadgetTypePass() = default;
        DefineGadgetTypePass(const DefineGadgetTypePass& pass){}
        //Pass options
        mlir::Pass::Option<MaskingMethod> parameterGadgetType{
                *this, 
                "type", 
                llvm::cl::desc("Gadget Type"),
                llvm::cl::values(
                    clEnumVal(hpc1, "HPC_1 based gadgets"),
                    clEnumVal(hpc2, "HPC_2 based gadgets")),
                llvm::cl::init(none)};
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerDefineGadgetTypePass();
    std::unique_ptr<mlir::Pass> createDefineGadgetTypePass();



    //// ***** Insert Gadget-Logic Pass *****
    ///
    /// Transformation pass that creates a shared and duplicated
    /// design, by duplicating and inserting the logic of gadgets.
    class InsertGadgetsLogicPass : public mlir::PassWrapper<
            InsertGadgetsLogicPass, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        InsertGadgetsLogicPass() = default;
        InsertGadgetsLogicPass(const InsertGadgetsLogicPass& pass){}
        //Define commandline arguments
        mlir::Pass::Option<int> parameterOrder{
                *this, 
                "order", 
                llvm::cl::desc("Side-channel security order of gadgets"),
                llvm::cl::init(2),
                llvm::cl::value_desc("int")};
        mlir::Pass::Option<int> parameterActiveOrder{
                *this, 
                "activeOrder", 
                llvm::cl::desc("Active security order of gadgets"),
                llvm::cl::init(2),
                llvm::cl::value_desc("int")};
        mlir::Pass::Option<bool> parameterAsModule{
                *this, 
                "asModule", 
                llvm::cl::desc("Instancate multiplication gadgets as modules"),
                llvm::cl::init(false),
                llvm::cl::value_desc("bool")};
        mlir::Pass::Option<bool> parameterPipelineGadgets{
                *this, 
                "pipeline", 
                llvm::cl::desc("Pipeline gadgets internally"),
                llvm::cl::init(false),
                llvm::cl::value_desc("bool")};
        //Pass execution
        void runOnOperation() override;
        //Function that creates a shared and duplicated
        //implementation of a given module. 
        secfir::ModuleOp maskAndDuplicateModule(
                secfir::ModuleOp &module, 
                std::vector<mlir::Attribute> encoding);
    };
    //Register and create functions
    void registerInsertGadgetsLogicPass();
    std::unique_ptr<mlir::Pass> createInsertGadgetsLogicPass();


    

    ///------------------------------------------------------------------------
    /// ***** Gadget Insertion *****
    ///
    /// * Functions that insert gadget operations
    /// * Functions that insert duplication and gadget logics
    ///-------------------------------------------------------------------------

    /// Function that inserts a DoubleSNI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertDoubleSniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    );

    /// Function that inserts a SNI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertSniMultiplication(
        secfir::AndPrimOp *andOp,
        mlir::OpBuilder *builder
    );

    /// Function that inserts a PINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertPiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    );

    /// Function that inserts a multiplication gadget that is both
    /// PINI and SNI, which replaces an AND operation, where the 
    /// references are replaced but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertSpiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    );

    /// Function that inserts a CINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertCiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    );

    /// Function that inserts an ICINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertIciniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    );

    /// Function that given a list of input ports shares and duplicates those
    /// ports. Only marked ports are shared, while all ports are duplicated.
    /// Does not handle case of flipped data types.
    ///
    /// context                     The current context
    /// ports                       List of input ports that should be shared and duplicated
    /// toShare                     List of attributes that indicate which inputs to share
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create
    /// sharedAndDuplicatedPorts    Resulting list of shared and duplicated ports
    void shareAndDuplicateInputPorts(
        mlir::MLIRContext *context,
        secfir::SmallVector<secfir::ModulePortInfo, 4> *ports,
        std::vector<mlir::Attribute> toShare,
        unsigned numberShares,
        unsigned numberDuplications,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts  
    );

    /// Function shares and duplicates a given list of output ports.
    /// Currently all ports are shared and duplicated. This function
    /// can only handle ports with flipped types.
    ///
    /// context                     Current context
    /// ports                       List of output ports to share and duplicate
    /// numberShares                Number of shares to create
    /// numberDuplications          Number of duplications to create
    /// sharedAndDuplicatedPorts    Resulting list of shared and duplicated ports
    void shareAndDuplicateOutputPorts(
        mlir::MLIRContext *context,
        secfir::SmallVector<secfir::ModulePortInfo, 4> *ports,
        unsigned numberShares,
        unsigned numberDuplications,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts
    );

    /// Function that adds a specified number of input ports for randomness
    /// to a given list of ports.
    ///
    /// context                     Current context
    /// numberRandomness            Number or ports to create
    /// startIndexFreshRandomness   Result that will hold the index of the first
    ///                                 port added by this function
    /// sharedAndDuplicatedPorts    List of ports that should be extended
    void addRandomnessPorts(
        mlir::MLIRContext *context,
        unsigned numberRandomness,
        unsigned *startIndexFreshRandomness,
        secfir::SmallVector<secfir::ModulePortInfo, 8> *sharedAndDuplicatedPorts
    );

    /// Function that shares and duplicates a given instruction with a given
    /// operation builder. Operations that should be shared and are no SCA or
    /// CA gadgets must have the attribute "ToShare".
    ///
    /// op                          Operation to share and duplicate
    /// opBuilder                   Operation builder used for IR manipulation
    /// sharedModule                The module where the shared and duplicated
    ///                                 operation will be placed in
    /// oldClock                    Clock of the unshared and not duplicated module
    /// valueMap                    Map from values to their shared and duplicated
    ///                                 counterparts
    /// dummyMap                    Map for shared and duplicated dummy values
    /// numberShares                Number of shares to create
    /// numberDuplications          Number of duplications to create
    /// startIndexFreshRandomness   Index of the first randomness in the port list
    ///                                 of the shared module
    /// operationId                 An ID used to name a potential module of a gadget
    /// asModule                    If true the gadget is placed in a separate module 
    /// pipelineGadget              If true, the gadget is pipelined internally
    void shareAndDuplicateOperation(
        mlir::Operation &op,
        mlir::OpBuilder opBuilder,
        secfir::ModuleOp sharedModule,
        secfir::Value oldClock,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
        unsigned numberShares,
        unsigned numberDuplications,
        unsigned startIndexFreshRandomness,
        unsigned operationId,
        bool asModule,
        bool pipelineGadget
    );
	
	/// Function that implements the tightProver algorithm, which verifies
    /// probing security of a combinatorial logic block and thereby identifies
    /// postions where an SNI refresh gadget needs to be inserted to fullfil
    /// probing security. The algorithm is taken from Belaid et al, "Tight Private
    /// Circuits: Achieving Probing Security with the Least Refreshing", 2018
    ///
    /// Only combinatorial logic blocks as XAG are supported, where AND gates are 
    /// replaced by SNI AND operations.
    ///
    /// combLogicBlock      The block of combinatorial logic that should be analysed
    /// builder             An operation builder for IR manipulation (only used for 
    ///                             constructive variant)
    /// numberRefGadgets    Memory address where the number of inserted refresh 
    ///                             gadgets will be written to (only used for 
    ///                             constructive variant)
    /// constructSecure     True => constructive variant; False => verification only
    bool tightProver(
        secfir::CombLogicOp combLogicBlock,
        mlir::OpBuilder &builder,
        unsigned *numberRefGadgets,
        bool constructSecure
    );

    /// Function that checks that a specific value has an SNI gadget in all
    /// its computation path, i.e., it is not influenced by an input without
    /// SNI gadget in between. If that is true for all output values of an NI 
    /// gadget then the gadget is SNI (Barthe et al. in "Strong Non-Interference 
    /// and Type Directed Higher-Order Masking", 2016)
    ///
    /// value       Value that should be checked
    bool checkSniOfNi(
        mlir::Value value
    );

    /// Function that ensures that all intermediate values are used only once,
    /// except as input for SNI refresh gadgets. This property ensures NI of the 
    /// combinatorial logic and can be used as first step to ensure SNI, according
    /// to Barthe et al. in "Strong Non-Interference and Type Directed Higher-Order
    /// Masking", 2016.
    ///
    /// logicBlock      The combinatorial logic that should be secured
    /// builder         An operation builder for IR manipulation
    void insertSniRefreshForNi(
        secfir::CombLogicOp logicBlock,
        mlir::OpBuilder builder,
        unsigned *numberRefGadgets
    );

    /// Function that inserts an SNI refresh gadget at the input
    /// of an operation. 
    ///
    /// input       Input that should be refreshed
    /// user        Operation that should use the refreshed value
    /// builder     An operation builder for IR manipulation
    void insertSniRefresh(
        mlir::Value *input,
        mlir::Operation *user,
        mlir::OpBuilder *builder
    );

    /// Function that inserts the logic of the DOM multiplication gadget.
    /// Algorithm in Cassiers et al. "Hardware Private Circuits:
    /// From Trivial Composition to Full Verification", 2020.
    /// We added a register at each output to ensure SNI.
    ///
    /// gadget              The SNI multiplication gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertDOMAnd(
            secfir::SniAndGadgetOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    );

    /// Function that inserts the logic of the SNI refresh gadget.
    /// DOM multiplication gadget with constant input b=(1,0,...,0)
    /// and registers at the outputs to ensure SNI. Intermediate registers
    /// that are obsolete for security are removed.
    ///
    /// gadget              The SNI refresh gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertDOMRefresh(
            secfir::SniRefreshOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    );

    /// Function that inserts the logic of a single HPC_1 gadget with a
    /// given operation builder. Algorithm in Cassiers et al. 
    /// "Hardware Private Circuits: From Trivial Composition to 
    /// Full Verification", 2020.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeHPC1(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedLhs,
            std::vector<mlir::Value> &sharedRhs,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk,
            bool pipeline
    );

    /// Function that inserts the logic of the HPC_2 gadget.
    /// Algorithm in Cassiers et al. "Hardware Private Circuits:
    /// From Trivial Composition to Full Verification", 2020.
    ///
    /// gadget              The PINI gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertHPC2(
            secfir::PiniAndGadgetOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    );

    /// Function that inserts the logic of the HPC_2 gadget with an
    /// additional output register, which makes it SNI as well.
    /// Algorithm in Cassiers et al. "Hardware Private Circuits:
    /// From Trivial Composition to Full Verification", 2020.
    ///
    /// gadget              The PINI gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertHPC2withOutputRegister(
            secfir::SniPiniAndGadgetOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    );


    /// Function that inserts the logic of a single HPC_2 gadget with a
    /// given operation builder. Algorithm in Cassiers et al. 
    /// "Hardware Private Circuits: From Trivial Composition to 
    /// Full Verification", 2020.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers 
    /// pipeline            If true gadget is pipelined internally            
    void placeHPC2(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedLhs,
            std::vector<mlir::Value> &sharedRhs,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk,
            bool pipeline
    );


    /// Function that inserts the logic of a single DOM multiplication 
    /// We add a register at each output to ensure SNI
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeDomMultiplication(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedLhs,
            std::vector<mlir::Value> &sharedRhs,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk
    );

    /// Function that inserts the logic of a single DOM refresh gadget. 
    /// We add a register at each output to ensure SNI
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedInput         Vector of shares of the LHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeDomRefresh(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedInput,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk
    );

    /// Function that inserts the logic of the HPC_1^C gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers  
    /// pipeline            If true gadget is pipelined internally      
    void placeCiniHPC1(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    );

    /// Function that inserts the logic of the HPC_2^C gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeCiniHPC2(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    );

    // Function that inserts the logic of the ICINI multiplication gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers       
    /// pipeline            If true, gadget is pipelined internally 
    void placeIciniMultiplicationLogic(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    );

    //// Function that inserts the logic of a binary gadget instead
    /// of a the correspondng gadget  operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create   
    /// gadgetId                    An ID used to name a module of the gadget
    /// asModule                    If true the gadget is placed in a separate module  
    /// pipelineGadget              If true, gadget is pipelined internally 
    void insertDuplicatedBinaryGadget(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            mlir::Value oldClock,
            unsigned startIndexFreshRandomness,
            unsigned numberShares,
            unsigned numberDuplications,
            unsigned gadgetId,
            bool asModule,
            bool pipelineGadget
    );

    // Function that inserts a module containing an SCA gadget at the 
    /// top of a given circuit. The gadgets can be HPC_2, HPC_2+, DOM
    /// multiplication, and DOM refresh. 
    ///
    /// location            Location of the new module
    /// op                  Operation defining the gadget type
    /// circuitOp           Circuit to which the module is added
    /// builder             An operation builder used for creation of the module
    /// numberShares        The number of input shares
    /// numberRandomness    The number of required randomness
    /// pipelineGadget      If true, gadget is pipelined internally
    void insertScaGadgetAsModule(
        mlir::Location location,
        mlir::Operation &op,
        secfir::CircuitOp &circuitOp,
        mlir::OpBuilder &builder,
        unsigned numberShares,
        unsigned numberRandomness,
        bool pipelineGadget
    );

    /// Function that inserts a module containing a combined gadget at the 
    /// top of a given circuit. The gadgets can be a CINI multiplication.
    ///
    /// location            Location of the new module
    /// op                  Operation defining the gadget type
    /// circuitOp           Circuit to which the module is added
    /// builder             An operation builder used for creation of the module
    /// numberShares        The number of input shares
    /// numberRandomness    The number of required randomness
    /// pipelineGadget      If true, the gadget is pipelined internally
    void insertCombinedGadgetAsModule(
        mlir::Location location,
        mlir::Operation &op,
        secfir::CircuitOp &circuitOp,
        mlir::OpBuilder &builder,
        unsigned numberShares,
        unsigned numberDuplications,
        unsigned numberRandomness,
        bool pipelineGadget
    );

    /// Fuction that inserts an instance of an SCA gadget
    /// that ins realized as module. For unary gadgets 
    /// sharedRhs can be an empty list.
    ///
    ///location             Location of the instantiation
    ///instanceName         A name for the instance
    ///moduleName           Name of the referenced module
    ///builder              A builder for IR creation
    ///sharedLhs            Shared first input of the gadget
    ///sharedRhs            Shared second input of the gadget
    ///randomness           List of random values for the gadget
    ///sharedResult         Place to store the results, needs to 
    ///                         be initialized to numberOfShare elements
    ///clock                The clock signal to use
    void insertInstanceOfScaGadget(
        mlir::Location location,
        mlir::StringAttr instanceName,
        mlir::FlatSymbolRefAttr moduleName,
        mlir::OpBuilder &builder,
        std::vector<mlir::Value> &sharedLhs,
        std::vector<mlir::Value> &sharedRhs,
        std::vector<mlir::Value> &randomness,
        std::vector<mlir::Value> &sharedResult,
        mlir::Value &clock,
        bool unaryGadget
    );

    ///Fuction that inserts an instance of a combined SCA gadget
    ///that ins realized as module.
    ///
    ///location             Location of the instantiation
    ///instanceName         A name for the instance
    ///moduleName           Name of the referenced module
    ///builder              A builder for IR creation
    ///sharedLhs            Shared first input of the gadget
    ///sharedRhs            Shared second input of the gadget
    ///randomness           List of random values for the gadget
    ///sharedResult         Place to store the results, needs to 
    ///                         be initialized to numberOfShare elements
    ///duplicatedClock      List of clock signals to use
    void insertInstanceOfCombinedGadget(
        mlir::Location location,
        mlir::StringAttr instanceName,
        mlir::FlatSymbolRefAttr moduleName,
        mlir::OpBuilder &builder,
        std::vector<std::vector<mlir::Value>> &sharedLhs,
        std::vector<std::vector<mlir::Value>> &sharedRhs,
        std::vector<mlir::Value> &randomness,
        std::vector<std::vector<mlir::Value>> &sharedResult,
        std::vector<mlir::Value> &duplicatedClock
    );

    /// Function that inserts the duplicated logic of a unary gadget instead
    /// of a the correspondng gadget operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create   
    void insertDuplicatedUnaryGadget(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            mlir::Value oldClock,
            unsigned startIndexFreshRandomness,
            unsigned numberShares,
            unsigned numberDuplications,
            unsigned gadgetId,
            bool asModule
    );

    /// Function that inserts the logic of a binary CA gadget instead of the
    /// corresponding gadget operation.
    ///
    /// op                          Gadget operation
    /// opBuilder                   An operation builder for IR manipulation
    /// valueMap                    A map from unshared to shared values
    /// dummyMap                    A map from unshared to shared dummy values
    /// moduleArguments             List of module arguments that contains fresh randomness
    /// oldClock                    Clock of the unshared and not duplicated module
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                     fresh randomness starts
    /// numberShares                The number of shares to create
    /// numberDuplications          The number of duplications to create  
    /// gadgetId                    ID that will be used to name a potential module instance
    /// asModule                    If true, the gadget will be realized in separate module 
    /// pipelineGadget              If true, the gadget is pipelined internally
    void insertCombinedBinaryGadget(
        mlir::Operation &op, 
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
        mlir::Block::BlockArgListType moduleArguments, 
        mlir::Value oldClock,
        unsigned startIndexFreshRandomness,
        unsigned numberShares,
        unsigned numberDuplications,
        unsigned gadgetId,
        bool asModule,
        bool pipelineGadget
    );

    /// Function that shares a node operation by removing it.
    ///
    /// nodeOp              The unshared node operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareNode(
        secfir::NodeOp nodeOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
        unsigned numberShares
    );

    /// Function that shares an output operation by marking all shares as outputs.
    ///
    /// outputOp            The unshared output operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// numberShares        The number of shares
    void shareOutput(
        secfir::OutputOp outputOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
        unsigned numberShares
    );

    /// Function that shares  and duplicates an output operation 
    /// by marking all shares and duplications as outputs.
    ///
    /// outputOp            The unshared output operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateOutput(
        secfir::OutputOp outputOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &oldToNewValueMap,
        unsigned numberShares,
        unsigned numberDuplications
    );

    /// Function that shares a NOT operation inverting the share with domain ID 0 
    /// and forwarding all other shares. 
    ///
    /// notOp               The unshared not operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareNot(
            secfir::NotPrimOp notOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    );

    /// Function that shares and duplicates a NOT operation by
    /// inverting the share with domain ID 0 and forwarding all other shares. 
    ///
    /// notOp               The unshared not operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMAp            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares to create
    /// numberDuplications  The number of duplications to create
    void shareAndDuplicateNot(
            secfir::NotPrimOp notOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    );

    /// Function that shares a XOR operation by creating a seperat instance for
    /// each share.
    ///
    /// xorOp               The unshared xor operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareXor(
            secfir::XorPrimOp xorOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    );

    /// Function that shares and duplicated an XOR operation by 
    /// creating a seperat instance for each share and duplication.
    ///
    /// xorOp               The unshared xor operation
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateXor(
            secfir::XorPrimOp xorOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    );

    /// Function that shares a register operation by creating a new register
    /// for each share domain.
    ///
    /// regOp               The unshared register operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareRegister(
            secfir::RegOp regOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    );

    /// Function that shares and duplicates a register operation by creating a new register
    /// for each share and duplication index.
    ///
    /// regOp               Register to be shared and duplicated
    /// opBuilder           Operation builder that is used for operation creation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    /// numberDuplications  The number of duplications
    void shareAndDuplicateRegister(
            secfir::RegOp regOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberShares,
            unsigned numberDuplications
    );

    /// Function that shares a connect operation by connecting each share of the
    /// source to the correspondng share of the destination
    ///
    /// regOp               The unshared register operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// numberShares        The number of shares
    void shareConnect(
            secfir::ConnectOp connectOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            unsigned numberShares
    );

    /// Function that duplicates a binary (nonlinear) operation by 
    /// creating a seperat instance for each duplication.
    ///
    /// op                  The binary operation to duplicate
    /// opBuilder           An operation builder for IR manipulation
    /// valueMap            A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberDuplications  The number of duplications
    void duplicateBinaryOp(
            mlir::Operation &op, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &valueMap,
            mlir::DenseMap<mlir::Value, std::vector<std::vector<mlir::Value>>> &dummyMap,
            unsigned numberDuplications
    );
}
}

#endif // !CIRCT_DIALECT_SECFIR_TIGHTPROVER_H