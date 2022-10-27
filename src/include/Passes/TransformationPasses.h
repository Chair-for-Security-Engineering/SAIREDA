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

#ifndef CIRCT_DIALECT_SECFIR_TRANSFORMATIONPASSES_H
#define CIRCT_DIALECT_SECFIR_TRANSFORMATIONPASSES_H

#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Ops.h"

#include "mlir/IR/Matchers.h"
#include "mlir/IR/PatternMatch.h"
#include "mlir/Pass/Pass.h"
#include "mlir/Pass/PassOptions.h"
#include "mlir/Pass/PassRegistry.h"
#include "mlir/IR/BlockAndValueMapping.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/CommandLine.h"

#include<z3++.h>

#include<list>

namespace circt {
namespace secfir {

		

		

        //-===---Security Transformations-----------------------------------------------

		class SetShareAttribute : public mlir::PassWrapper<
				SetShareAttribute, 
				mlir::OperationPass<circt::secfir::CircuitOp>
		> {
		public:
			//Constructors
			SetShareAttribute() = default;
			SetShareAttribute(const SetShareAttribute& pass) {}
		
			void runOnOperation() override;
		};
		void registerSetShareAttributePass();
		std::unique_ptr<mlir::Pass> createSetShareAttributePass();

		

		

		enum DistributionRule {
  			pini_rule, sni_rule, std_rule
		};
		enum UniqueRandomnessPerGadget {
  			non, t_bit
		};
		class DistributeRandomness : public mlir::PassWrapper<
				DistributeRandomness, 
				mlir::OperationPass<secfir::CircuitOp>
		>{
		public:
			DistributeRandomness() = default;
			DistributeRandomness(const DistributeRandomness& pass){}

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
					llvm::cl::init(0),
					llvm::cl::value_desc("int")};
			mlir::Pass::Option<DistributionRule> parameterDistributionRule{
					*this, 
					"rule", 
					llvm::cl::desc("Rule on which randomness distribution is done"),
					llvm::cl::values(
						clEnumValN(pini_rule, "pini", "Randomness always used for same share indices and no pair of random values used in two gadgets"),
						clEnumValN(sni_rule, "sni", "No pair of random values used in two gadgets and independent inputs"),
						clEnumValN(std_rule, "std", "Standard distribution (fresh randomness for all gadgets)")
					),
					llvm::cl::init(pini_rule)};
			mlir::Pass::Option<UniqueRandomnessPerGadget> parameterUniqueRandomnessPerGadget{
					*this, 
					"uniqueRand", 
					llvm::cl::desc("The rule for whether and how to use unique randomness for each gadget"),
					llvm::cl::values(
						clEnumValN(non, "non", "All random bits are potentially reused"),
						clEnumValN(t_bit, "t", "First t random values of each gadget are used uniquely")
					),
					llvm::cl::init(non)};
			mlir::Pass::Option<unsigned> parameterMaxSetSize{
					*this, 
					"maxSetSize", 
					llvm::cl::desc("Maximum number of gadgets that are put in one set of parallel gadgets"),
					llvm::cl::init(0),
					llvm::cl::value_desc("unsigned")};
			//Define statistics
			mlir::Pass::Statistic gadgetsStatistic{this, "gadgets", "The number of gadgets"};
			mlir::Pass::Statistic randomnessPerGadgetStatistic{this, "bits of randomness used per gadget", "The number randomness required per gadget"};
			mlir::Pass::Statistic randomnessStatistic{this, "bits of randomness used", "The number of randomness bits used all over the design"};
			mlir::Pass::Statistic savedRandomnessStatistic{this, "bits of randomness removed", "The number of randomness bits that where removed compared to a naive distribution"};
			mlir::Pass::Statistic numSetStatistic{this, "clusters", "The number of generated clusters"};
			mlir::Pass::Statistic meanSetSizeStatistic{this, "set size (mean) * 10^2", "The average size of the found clusters multiplied by 10^2"};
			mlir::Pass::Statistic minSetSizeStatistic{this, "gadgets in smallest set", "The number of gadgets in the smallest cluster"};
			mlir::Pass::Statistic maxSetSizeStatistic{this, "gadgets in largest set", "The number of gadgets in the largest cluster"};
			
			void runOnOperation() override;
		};

		void registerDistributeRandomnessPass();
		std::unique_ptr<mlir::Pass> createDistributeRandomnessPass();
}
}
#endif // !CIRCT_DIALECT_SECFIR_TRANSFORMATIONPASSES_H