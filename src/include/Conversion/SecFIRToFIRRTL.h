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
#ifndef CIRCT_CONVERSION_SECFIRTOFIRRTL_H
#define CIRCT_CONVERSION_SECFIRTOFIRRTL_H

#include "mlir/Pass/Pass.h"
#include "mlir/Transforms/DialectConversion.h"
#include "mlir/Transforms/Utils.h"
#include "mlir/IR/BlockAndValueMapping.h"

#include "circt/Dialect/FIRRTL/Dialect.h"
#include "circt/Dialect/FIRRTL/Ops.h"
#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Ops.h"

namespace circt {
	namespace secfir {
        struct SecFIRToFIRRTLConversionPass: public mlir::PassWrapper<SecFIRToFIRRTLConversionPass, 
                mlir::OperationPass<secfir::CircuitOp>> {
            void getDependentDialects(mlir::DialectRegistry &registry) const override {
                registry.insert<secfir::SecFIRDialect>();
            }
            void runOnOperation() final;
        };
        
        std::unique_ptr<mlir::Pass> createSecFIRToFIRRTLConversionPass();
        void registerSecFIRToFIRRTLConversionPass();
    }
}

#endif //CIRCT_CONVERSION_SECFIRTOFIRRTL_H