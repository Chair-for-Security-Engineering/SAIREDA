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

		/// An transformation pass that inserts CombLogicOp operations by finding combinational 
    	/// networks within the module and combining them inside a CombLogicOp.
    	class InsertCombinationalNetworkHierarchy : public mlir::PassWrapper<
				InsertCombinationalNetworkHierarchy, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			InsertCombinationalNetworkHierarchy() = default;
			InsertCombinationalNetworkHierarchy(
					const InsertCombinationalNetworkHierarchy& pass) {}
		
			void runOnOperation() override;			
		};
		void registerInsertCombinationalNetworkHierarchyPass();
		std::unique_ptr<mlir::Pass> createInsertCombinationalNetworkHierarchyPass();

		/// A transformation pass that removes all CombLogicOp operations by copying all 
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
		
			void runOnOperation() override;			
		};
		void registerFlattenCombinationalNetworkHierarchyPass();
		std::unique_ptr<mlir::Pass> createFlattenCombinationalNetworkHierarchyPass();

		class ToXAG : public mlir::PassWrapper<
				ToXAG, 
				mlir::OperationPass<secfir::CircuitOp>
		>{
		public:
			ToXAG() = default;
			ToXAG(const ToXAG& pass){}

			void runOnOperation() override;
		};
		void registerToXAGPass();
		std::unique_ptr<mlir::Pass> createToXAGPass();

        //-===---Security Transformations-----------------------------------------------

		/// Transformation that transforms a module into its masked form, 
		/// by replacing operations with its PINI_1 implementation.
		///
		/// Currently, modules need to be flattend with respect to CombLogicOps
		class MaskPini1 : public mlir::PassWrapper<
				MaskPini1, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			MaskPini1() = default;
			MaskPini1(const MaskPini1& pass) {}
		
			void runOnOperation() override;
		private:
			unsigned int numberShares = 2;
        	void maskCircuit(secfir::CircuitOp &circuit);
			circt::secfir::ModuleOp maskModule(secfir::ModuleOp &module, 
				const char* encoding);
			
		};
		void registerMaskPini1Pass();
		std::unique_ptr<mlir::Pass> createMaskPini1Pass();

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

		enum MaskingMethod {
  			pini, doubleSni, spini, sni, ni, probSec, probSecNoTightProve
		};
		/// Transformation pass that replaces every AND gate with a 
    	/// side-channel secure gadget.
		class InsertGadgetsPass : public mlir::PassWrapper<
				InsertGadgetsPass, 
				mlir::OperationPass<secfir::CircuitOp>
		>{
		public:
			InsertGadgetsPass() = default;
			InsertGadgetsPass(const InsertGadgetsPass& pass){}

			mlir::Pass::Option<MaskingMethod> parameterMaskingType{
					*this, 
					"masking", 
					llvm::cl::desc("Masking method"),
					llvm::cl::values(
						clEnumVal(sni, "Masking with SNI gadgets"),
						clEnumVal(pini, "Masking with PINI gadgets"),
						clEnumVal(spini, "Masking with gadgets that are both SNI and PINI"),
						clEnumVal(doubleSni, "Masking with double-SNI gatgets"),
						clEnumVal(ni, "Masking with SNI gatgets, where the result is NI secure"),
						clEnumVal(probSec, "Masking with SNI gatgets, where the result is probing secure"),
						clEnumVal(probSecNoTightProve, "Masking with SNI AND gadgets, should only be used when known that the result is probing secure!")),
					llvm::cl::init(pini)};

			mlir::Pass::Statistic refSniGadgetsStatistic{this, "SNI refresh gadgets", "The number of inserted SNI refresh gadgets"};
			mlir::Pass::Statistic mulSniGadgetsStatistic{this, "SNI multiplication gadgets", "The number of inserted SNI multiplication gadgets"};
			mlir::Pass::Statistic piniGadgetsStatistic{this, "PINI multiplication gadgets", "The number of inserted PINI multiplication gadgets"};
			mlir::Pass::Statistic spiniGadgetsStatistic{this, "SPINI multiplication gadgets", "The number of inserted SPINI multiplication gadgets"};
			mlir::Pass::Statistic secureBlockStatistic{this, "secure blocks", "The number of secure combinatorial logic blocks"};
			mlir::Pass::Statistic overallStatistic{this, "overall blocks", "The number of insecure combinatorial logic blocks"};

			void runOnOperation() override;
		};
		void registerInsertGadgetsPass();
		std::unique_ptr<mlir::Pass> createInsertGadgetsPass();

		class InsertGadgetsLogicPass : public mlir::PassWrapper<
				InsertGadgetsLogicPass, 
				mlir::OperationPass<secfir::CircuitOp>
		>{
		public:
			InsertGadgetsLogicPass() = default;
			InsertGadgetsLogicPass(const InsertGadgetsLogicPass& pass){}

			//Define commandline arguments
			mlir::Pass::Option<int> parameterOrder{
					*this, 
					"order", 
					llvm::cl::desc("Side-channel security order of gadgets"),
					llvm::cl::init(2),
					llvm::cl::value_desc("int")};

			void runOnOperation() override;
			secfir::ModuleOp maskModule(
            		secfir::ModuleOp &module, 
            		std::vector<mlir::Attribute> encoding);
		};
		void registerInsertGadgetsLogicPass();
		std::unique_ptr<mlir::Pass> createInsertGadgetsLogicPass();


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
			//Define statistics
			mlir::Pass::Statistic gadgetsStatistic{this, "gadgets", "The number of gadgets"};
			mlir::Pass::Statistic randomnessPerGadgetStatistic{this, "bits of randomness used per gadget", "The number randomness required per gadget"};
			mlir::Pass::Statistic randomnessStatistic{this, "bits of randomness used", "The number of randomness bits used all over the design"};
			mlir::Pass::Statistic savedRandomnessStatistic{this, "bits of randomness removed", "The number of randomness bits that where removed compared to a naive distribution"};
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