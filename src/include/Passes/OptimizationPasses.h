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

#ifndef CIRCT_DIALECT_SECFIR_OPTIMIZATIONPASSES_H
#define CIRCT_DIALECT_SECFIR_OPTIMIZATIONPASSES_H

#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Ops.h"
#include "Util/BooleanChain.h"
#include "Util/util.h"

#include "mlir/IR/Matchers.h"
#include "mlir/IR/PatternMatch.h"
#include "mlir/Pass/Pass.h"
#include "mlir/Pass/PassOptions.h"
#include "mlir/IR/BlockAndValueMapping.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "mlir/Transforms/GreedyPatternRewriteDriver.h"

#include<z3++.h>

#include <list>
#include <set>

namespace circt {
	namespace secfir {

		///------------------------------------------------------------------------
		/// ***** Passes *****
		///
		/// * Pass that removes all redundant operations 
		/// * Pass that removes node operations
		/// * Pass that removes double-not operations
		/// * Pass for logic optimization via cut rewriting
		///------------------------------------------------------------------------

		/// ***** Remove Node-Operations Pass *****
		///
		/// An optimization pass that goes though a modules and removes all
		/// redundant operations by replacing them with the result of the first
		/// of the redundant operations.
		///
		/// Can violate security properties with respect to redundancy (FIA).
        class ReplaceRedundantOperations : public mlir::PassWrapper<
				ReplaceRedundantOperations, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			ReplaceRedundantOperations() = default;
			ReplaceRedundantOperations(const ReplaceRedundantOperations& pass) {}
			//Define statistics
			mlir::Pass::Statistic removedOpsStatistic{this, 
						"operations removed", "The number of removed operations"};
			//Pass execution
			void runOnOperation() override;			
		};
		//Register and create functions
		void registerReplaceRedundantOperationsPass();
		std::unique_ptr<mlir::Pass> createReplaceRedundantOperationsPass();


		/// ***** Remove Node-Operations Pass *****
		///
		/// An optimization pass that goes though all operations of 
		/// a module and removes all NodeOp operations, by replacing 
		/// all usages with the corresponding input.
		class RemoveNodeOpPass : public mlir::PassWrapper<
				RemoveNodeOpPass, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			RemoveNodeOpPass() = default;
			RemoveNodeOpPass(const RemoveNodeOpPass& pass) {}
			//Pass execution
			void runOnOperation() override;			
		};
		//Register and create functions
		void registerRemoveNodeOpPass();
		std::unique_ptr<mlir::Pass> createRemoveNodeOpPass();
    

		
		/// ***** Remove Double-Not Pass *****
		///
		/// Pass that goes though all modules an removes all double NOT operations,
		/// i.e. NOT(NOT()).
		class RemoveDoubleNotOpPass : public mlir::PassWrapper<
				RemoveDoubleNotOpPass, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			RemoveDoubleNotOpPass() = default;
			RemoveDoubleNotOpPass(const RemoveDoubleNotOpPass& pass) {}
			//Pass execution
			void runOnOperation() override;			
		};
		//Register and create functions
		void registerRemoveDoubleNotOpPass();
		std::unique_ptr<mlir::Pass> createRemoveDoubleNotOpPass();
    }
}

#endif // !CIRCT_DIALECT_SECFIR_OPTIMIZATIONPASSES_H