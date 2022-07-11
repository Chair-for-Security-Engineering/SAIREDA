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
#ifndef CIRCT_DIALECT_SECFIR_OPTIMIZERANDOMNESS_H
#define CIRCT_DIALECT_SECFIR_OPTIMIZERANDOMNESS_H

#include<vector>
#include<set>
#include<z3++.h>

#include "SecFIR/Ops.h"
#include "Util/util.h"

namespace circt {
namespace secfir {

    // Function that searches for a distribution of randomness for a set of parallel
    /// SNI gadgets using the SMT solver Z3, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously. 
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires (determined by the order)
    /// numberRandomness:   number of random elements available overall
    /// assignment:         pointer to a data structure that is used for the found assignment
    bool sniDistributionSMT(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                unsigned numberRandomness, 
                std::vector<std::vector<unsigned>> *assignment
    );

    /// Recursive function that searches for a valid next random value (fulfilling the 
    /// conditions for random reuse in parallel SNI gadgets) given a valid partial 
    /// assignment.
    ///
    /// assignment:         Valid partial assignment that was already found (can be empty)
    /// start:              Index of the randomness were the alg. starts looking
    /// randomnessParGate:  Number of values required (length of final assignment)
    /// numberRandomness:   Number of overall available randomness
    /// pairs:              List of pairs of indices that are already used and, hence, 
    ///                         forbidden, pairs are (i, pairs[i][0]),...,(i, pairs[i][n])
    bool findAssignmentSni(
                std::vector<unsigned> *assignment,
                unsigned start,
                unsigned randomnessPerGate,
                unsigned numberRandomness,
                std::vector<std::set<unsigned>> *pairs
    );

    /// Function that searches for a distribution of randomness for a set of parallel
    /// SNI gadgets using a heuristic algorithm, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously.
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires 
    ///                           (determined by the security order)
    /// assignment:         pointer to a data structure that is used for the found assignment
    unsigned sniDistributionHeuristic(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                std::vector<std::vector<unsigned>> *assignment,
                std::vector<unsigned> *usedRandomness
    );

    /// Recursive function that searches for a valid next random value (fulfilling the 
    /// conditions for random reuse in parallel PINI gadgets) given a valid partial 
    /// assignment.
    ///
    /// assignment:         Valid partial assignment that was already found (can be empty)
    /// index:              Postion for which a value should be found
    /// randomnessParGate:  Number of values required (length of final assignment)
    /// pairs:              List of pairs of indices that are already used and, hence, 
    ///                         forbidden, pairs are (i, pairs[i][0]),...,(i, pairs[i][n])
    /// fixed:              List of indices that can only used at a fixed postion,
    ///                          where fixed[i] contains all values that can be used at 
    ///                          postion i
    /// free:               List of indices that can be used at any postion
    bool findAssignmentPini(
                std::vector<unsigned> *assignment,
                unsigned index,
                unsigned randomnessPerGate,
                std::vector<std::set<unsigned>> *pairs,
                std::vector<std::set<unsigned>> *fixed,
                std::vector<unsigned> *free
    );

    /// Function that searches for a distribution of randomness for a set of parallel
    /// PINI gadgets using a heuristic algorithm, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously and reused 
    /// random values are always used at the same postion. 
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires 
    ///                           (determined by the security order)
    /// assignment:         pointer to a data structure that is used for the found assignment
    unsigned piniDistributionHeuristic(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                std::vector<std::vector<unsigned>> *assignment,
                std::vector<unsigned> *usedRandomness
    );

    /// Recursive function that adds all gadgets to the list of dependent
    /// gadgets for a specific gadget starting from the provided operation.
    ///
    /// dependentOp:    the gadget we are searching dependent gadgats for
    /// op:             start operation for the recursive tree traversal
    /// dependentOps:   datastructure that contains for each already determined 
    ///                     gadgets the list of other gadgets it depends on
    void addDependentGadgets(
                mlir::Operation *dependentOp,
                mlir::Operation *op,
                mlir::DenseMap<mlir::Operation*, std::vector<mlir::Operation*>> &dependentOps
    );

    /// Function that determines for the inputs of all multiplication and 
    /// refresh gadgets (PINI and SNI) on which other gadget outputs they depend.
    ///
    /// module:          module that should be analysed
    /// dependentOps:    datastructure that will contain for each gadgets the 
    ///                     list of other gadgets it depends on
    void determineDependentGadgets(
            secfir::ModuleOp *module,
            mlir::DenseMap<mlir::Operation*, std::vector<mlir::Operation*>> &dependentOps
    );

    /// Function that determines the list of values a specifc value depend on.
    ///
    /// operations:         the list of operations the analysis will be done for
    /// dependentValues:    datastructure that will contain the mapping from values
    ///                         to the list of values it depends on
    void determineDependentValues(
        mlir::Block::OpListType &operations,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues
    );

    /// Function that determines the list of values and gadgets a specifc value depend on.
    /// Does currently only work with designs where all inputs to an operation are already
    /// defined.
    ///
    /// operations:         the list of operations the analysis will be done for
    /// dependentValues:    datastructure that will contain the mapping from values
    ///                         to the list of values it depends on
    /// dependentOps:    datastructure that will contain for each gadgets the 
    ///                     list of other gadgets it depends on
    void determineDependentValuesAndGadgets(
        mlir::Block::OpListType &operations,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps
    );

    /// Function that determines sets of parallel gadgets 
    /// (inputs is independent of any outputs) using a simple 
    /// heuristic: A gadget is always put in the first set it fits in.
    ///
    /// gadgets:        list of gadgets
    /// dependentOps:   mapping from every gadget to a list of gadgets
    ///                     it despends on
    /// parallelOps:    datastructure that will contain the sets of 
    ///                     parallel gadgets      
    void determineParallelGadgetsFirstFitHeuristic(
        std::vector<mlir::Operation *> &gadgets,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps,
        std::vector<std::vector<mlir::Operation*>> &parallelOps
    );

    /// Function that extends the set of gadgets one gadget depends on by all
    /// gadgets that get as input some dependent value to the input of the gadget.
    /// This is required for parallel SNI gates, as there the inputs need to be 
    /// independent.
    ///
    /// gadgets:            List of gadgets
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    /// dependentValues:    Mapping from values to values that value depends on. 
    void addDependentInputGadgets(
        std::vector<mlir::Operation*> gadgets,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues
    );

    /// Function that extends the set of gadgets one gadget depends on by all
    /// gadgets where the output is combined at some point in the module. This
    /// is necessary for a cluster of parallel gadgets where all randomness 
    /// should potentially be reused.
    ///
    /// operations          List of operations in module
    /// gadgets:            List of gadgets
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    /// dependentValues:    Mapping from values to values that value depends on. 
    void addCombinedOutputGadgets(
        //mlir::Block::OpListType &operations,
        std::vector<mlir::Operation*> gadgets,
        mlir::DenseMap<mlir::Operation*, std::vector<mlir::Operation*>> &dependentOps,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues
    );


    /// Optimized version of a function that extends the set of gadgets one 
    /// gadget depends on by all gadgets where the output is combined at some 
    /// point in the module. This is necessary for a cluster of parallel gadgets 
    /// where all randomness should potentially be reused. 
    /// Uses the fact, that an operation is dependent on all gadgets it combines
    /// and that SNI and output gadgets are the operations with the most dependencies.
    ///
    /// operations          List of operations in module
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    void addCombinedOutputGadgetsOpt(
         mlir::Block::OpListType &operations,
         mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps
    );


}
}

#endif // !CIRCT_DIALECT_SECFIR_OPTIMIZERANDOMNESS_H