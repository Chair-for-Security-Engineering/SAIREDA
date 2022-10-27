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

#ifndef CIRCT_DIALECT_SECFIR_OPTIMIZELATENCY_H
#define CIRCT_DIALECT_SECFIR_OPTIMIZELATENCY_H

#include "SecFIR/Ops.h"

#include "mlir/Pass/Pass.h"
#include "mlir/IR/Builders.h"

namespace circt {
namespace secfir {


    ///------------------------------------------------------------------------
    /// ***** Passes *****
    ///
    /// * Pass that optimizes input order for gadgets with asynchon latency 
    ///     at gadget level
    ///------------------------------------------------------------------------

    //// ***** Optimize Asynchon Gadget Pass *****
    ///
    /// Transformation pass that switches the order of inputs
    /// for gadgets with asynchon latency, such that the lhs input 
    /// is dependent on less gadgets.
    class OptimizeAsynchonGadgetLatencyPass : public mlir::PassWrapper<
            OptimizeAsynchonGadgetLatencyPass, 
            mlir::OperationPass<secfir::CircuitOp>
    >{
    public:
        //Constructors
        OptimizeAsynchonGadgetLatencyPass() = default;
        OptimizeAsynchonGadgetLatencyPass(const OptimizeAsynchonGadgetLatencyPass& pass){}
        //Define statistics
			mlir::Pass::Statistic switchStatistic{this, 
						"switches", "The number of input switches performed"};
        //Pass execution
        void runOnOperation() override;
    };
    //Register and create functions
    void registerOptimizeAsynchonGadgetLatencyPass();
    std::unique_ptr<mlir::Pass> createOptimizeAsynchonGadgetLatencyPass();


}
}

#endif // !CIRCT_DIALECT_SECFIR_OPTIMIZELATENCY_H