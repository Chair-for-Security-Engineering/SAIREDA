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

#ifndef CIRCT_DIALECT_SECFIR_PASSES_H
#define CIRCT_DIALECT_SECFIR_PASSES_H

#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Ops.h"

#include "mlir/IR/Matchers.h"
#include "mlir/IR/PatternMatch.h"
#include "mlir/Pass/Pass.h"
#include "mlir/IR/BlockAndValueMapping.h"
#include "llvm/ADT/SmallPtrSet.h"

#include<list>

namespace circt {
	namespace secfir {
        //-===---Data types----------------------------------------------------
		
		//Data structure for signals and their attached security level.
		class ModuleSecureSignals {
		private:
			const char* module;
			std::list<const char*> signals;
			std::list<int> securityLevels;
		public:
			//Constructor
			ModuleSecureSignals(
					const char* module, 
					std::list<const char*> signals, 
					std::list<int> securityLevels
			) : module(module), signals(signals), securityLevels(securityLevels) {}

			const char* getModuleName() { return module; }
			std::list<const char*> getSignals() { return signals; }
			std::list<int> getSecurityLevels() { return securityLevels; }

		};

		//-===---Attributes----------------------------------------------------
	
		//Define a security level attribute
		class SecurityLevelAttribute : public mlir::Attribute::AttrBase<
				SecurityLevelAttribute, 
				mlir::Type, mlir::TypeStorage
		> {
		public:
			using Base::Base;
		};

		//-===---Passes--------------------------------------------------------
		std::unique_ptr<mlir::Pass> createLowerToNetSecFIRPass();

		
		
        		
		//-===---Util Functions------------------------------------------------

		//void parseXmlFile(const char*, std::list<secfir::ModuleSecureSignals>);


		//-===---Pass for Experimentation--------------------------------------
		class ExperimentPass : public mlir::PassWrapper<
				ExperimentPass, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			ExperimentPass() = default;
			ExperimentPass(const ExperimentPass& pass) {}
		
			void runOnOperation() override;			
		};
		void registerExperimentPass();
		std::unique_ptr<mlir::Pass> createExperimentPass();


		//-===---Pass for Latency--------------------------------------
		class LatencyPass : public mlir::PassWrapper<
				LatencyPass, 
				mlir::OperationPass<secfir::CircuitOp>
		> {
		public:
			//Constructors
			LatencyPass() = default;
			LatencyPass(const LatencyPass& pass) {}

			mlir::Pass::Statistic maxLatencyStatistic{this, "latency", "maximal latency from all Output"};
			mlir::Pass::Statistic pipelineRequirementStatistic{this, "pipelined", "1 pipelined, 0 pipiline required"};
		
			void runOnOperation() override;			
		};
		void registerLatencyPass();
		std::unique_ptr<mlir::Pass> createLatencyPass();
    }
}

#endif // !CIRCT_DIALECT_SECFIR_PASSES_H
