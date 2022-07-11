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
#include "mlir/Pass/Pass.h"
#include "mlir/Transforms/DialectConversion.h"

#include "SecFIR/SecFIRDialect.h"
#include "Passes/Passes.h"
#include "SecFIR/Ops.h"

namespace {
struct LowSecFIRToNetFIRLoweringPass
    : public mlir::PassWrapper<LowSecFIRToNetFIRLoweringPass, 
    mlir::OperationPass<circt::secfir::CircuitOp>> {
        void getDependentDialects(mlir::DialectRegistry &registry) const override {
            registry.insert<circt::secfir::SecFIRDialect>();
        }
        void runOnOperation() final;
    };
}

// Lowering pass from Low SecFIR to Netlist SecFIR
void LowSecFIRToNetFIRLoweringPass::runOnOperation() {
    // The first thing to define is the conversion target. This will define the
    // final target for this lowering.
    mlir::ConversionTarget target(getContext());

    //Legalize structural operations of SecFIR
    target.addLegalOp<circt::secfir::CircuitOp>();
    target.addLegalOp<circt::secfir::ModuleOp>();
    target.addLegalOp<circt::secfir::ConnectOp>();
    target.addLegalOp<circt::secfir::DoneOp>();
    target.addLegalOp<circt::secfir::NodeOp>();
    target.addLegalOp<circt::secfir::RegOp>();


    //Legalize AND operation of UInt with width 1
    target.addDynamicallyLegalOp<circt::secfir::AndPrimOp>(
        [](circt::secfir::AndPrimOp op) {
            //Verify that all input signals are of type UInt with width 1.
            return (op.lhs().getType().isa<circt::secfir::UIntType>() &&
            op.lhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1 &&
            op.rhs().getType().isa<circt::secfir::UIntType>() &&
            op.rhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1);
        });
    //Legalize OR operation of UInt with width 1
    target.addDynamicallyLegalOp<circt::secfir::OrPrimOp>(
        [](circt::secfir::OrPrimOp op) {
            //Verify that all input signals are of type UInt with width 1.
            return (op.lhs().getType().isa<circt::secfir::UIntType>() &&
            op.lhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1 &&
            op.rhs().getType().isa<circt::secfir::UIntType>() &&
            op.rhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1);
        });
    //Legalize XOR operation of UInt with width 1
    target.addDynamicallyLegalOp<circt::secfir::XorPrimOp>(
        [](circt::secfir::XorPrimOp op) {
            //Verify that all input signals are of type UInt with width 1.
            return (op.lhs().getType().isa<circt::secfir::UIntType>() &&
            op.lhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1 &&
            op.rhs().getType().isa<circt::secfir::UIntType>() &&
            op.rhs().getType().cast<circt::secfir::UIntType>().getWidth() == 1);
        });
    //Legalize NOT operation of UInt with width 1
    target.addDynamicallyLegalOp<circt::secfir::NotPrimOp>(
        [](circt::secfir::NotPrimOp op) {
            //Verify that all input signals are of type UInt with width 1.
            return (op.input().getType().isa<circt::secfir::UIntType>() &&
            op.input().getType().cast<circt::secfir::UIntType>().getWidth() == 1);
        });
    //Legalize constant operation of UInt with width 1
    target.addDynamicallyLegalOp<circt::secfir::ConstantOp>(
        [](circt::secfir::ConstantOp op) {
            //Verify that all input signals are of type UInt with width 1.
            return (op.result().getType().isa<circt::secfir::UIntType>() &&
            op.result().getType().cast<circt::secfir::UIntType>().getWidth() == 1);
        });

    //Forbid everything else from SecFIR
    target.addIllegalDialect<circt::secfir::SecFIRDialect>();

    //Define lowering passes (currently empty)
    mlir::OwningRewritePatternList patterns;

    //Execute actual lowering
    if (mlir::failed(mlir::applyFullConversion(getOperation(), target, std::move(patterns))))
    signalPassFailure();
}

  std::unique_ptr<mlir::Pass> circt::secfir::createLowerToNetSecFIRPass() {
  return std::make_unique<LowSecFIRToNetFIRLoweringPass>();
}
    