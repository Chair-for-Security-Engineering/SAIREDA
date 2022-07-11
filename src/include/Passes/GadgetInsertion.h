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
}
}

#endif // !CIRCT_DIALECT_SECFIR_TIGHTPROVER_H