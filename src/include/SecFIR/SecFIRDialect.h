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

//===- SecFIR Dialect Decleration -===
// 
// SecFIR is a security extension to FIRRTL
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLDialect.h)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// 
//===----------------------------------===**/

#ifndef CIRCT_DIALECT_SECFIR_DIALECT_H
#define CIRCT_DIALECT_SECFIR_DIALECT_H

#include "mlir/IR/Dialect.h"
#include "mlir/IR/OpDefinition.h"
#include "SecFIR/Traits.h"
#include "mlir/Interfaces/ControlFlowInterfaces.h"

namespace circt {
	namespace secfir {
		
		struct SecurityLevelAttributeStorage;	
		class SecFIRType;	

		//-===---Dialect definition--------------------------------------------
		class SecFIRDialect : public mlir::Dialect {
		public:
			/// Create the dialect in the given `context`.
			explicit SecFIRDialect(mlir::MLIRContext* ctx);
  			~SecFIRDialect();

			mlir::Type parseType(mlir::DialectAsmParser &parser) const override;
  			void printType(mlir::Type, mlir::DialectAsmPrinter &) const override;
			void printAttribute(mlir::Attribute, mlir::DialectAsmPrinter &) const override;
			
			mlir::Operation *materializeConstant(mlir::OpBuilder &builder, mlir::Attribute value, 
								mlir::Type type, mlir::Location loc) override;

			static llvm::StringRef getDialectNamespace() { return "secfir"; }
		};

		/// If the specified attribute list has a secfir.name attribute, return its
		/// value.
		mlir::StringAttr getSecFIRNameAttr(llvm::ArrayRef<mlir::NamedAttribute> attrs);

		/// Register all of the SecFIR transformation passes with the PassManager.
		void registerSecFIRPasses();

}		
}

// Pull in all enum type definitions and utility function declarations.
#include "SecFIREnums.h.inc"



#endif // !CIRCT_DIALECT_SECFIR_DIALECT_H
