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

//===----------------------------------------------------------------------===//
//
// This file implements the dialect for SecFIR: custom type parsing and
// operation verification.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/lib/Dialect/FIRRTL/FIRRTLDialect.cpp)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//



#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Types.h"
#include "SecFIR/Ops.h"
#include "SecFIR/Attributes.h"
#include "Passes/Passes.h"

#include "mlir/IR/DialectImplementation.h"


using namespace circt::secfir;

//===----------------------------------------------------------------------===//
// Dialect specification.
//===----------------------------------------------------------------------===//

void SecFIRDialect::printType(Type type, DialectAsmPrinter &os) const {
  type.cast<SecFIRType>().print(os.getStream());
}

void SecFIRDialect::printAttribute(mlir::Attribute attr, mlir::DialectAsmPrinter &os) const {
	if(attr.isa<secfir::ValueAttr>()){
		ValueAttr par = attr.dyn_cast<secfir::ValueAttr>();
		par.getValue().print(os.getStream());
	}
}

// If the specified attribute set contains the secfir.name attribute, return it.
StringAttr circt::secfir::getSecFIRNameAttr(llvm::ArrayRef<mlir::NamedAttribute> attrs) {
  for (auto &argAttr : attrs) {
    // FIXME: We currently use secfir.name instead of name because this makes
    // the FunctionLike handling in MLIR core happier.  It otherwise doesn't
    // allow attributes on module parameters.
    if (argAttr.first != "secfir.name")
      continue;

    return argAttr.second.dyn_cast<StringAttr>();
  }

  return StringAttr();
}

namespace {
	// We implement the OpAsmDialectInterface so that SecFIR dialect operations
	// automatically interpret the name attribute on function arguments and
	// on operations as their SSA name.
	struct SecFIROpAsmDialectInterface : public mlir::OpAsmDialectInterface {
		using OpAsmDialectInterface::OpAsmDialectInterface;

		/// Get a special name to use when printing the given operation. See
		/// OpAsmInterface.td#getAsmResultNames for usage details and documentation.
		void getAsmResultNames(mlir::Operation *op,
								mlir::OpAsmSetValueNameFn setNameFn) const override {
			// Many secfir dialect operations have an optional 'name' attribute.  If
			// present, use it.
			if (op->getNumResults() > 0)
			if (auto nameAttr = op->getAttrOfType<StringAttr>("name"))
				setNameFn(op->getResult(0), nameAttr.getValue());

			// For constants in particular, propagate the value into the result name to
			// make it easier to read the IR.
			if (auto constant = dyn_cast<circt::secfir::ConstantOp>(op)) {
			auto intTy = constant.getType().dyn_cast<IntType>();

			// Otherwise, build a complex name with the value and type.
			SmallString<32> specialNameBuffer;
			llvm::raw_svector_ostream specialName(specialNameBuffer);
			specialName << 'c';
			if (intTy) {
				constant.value().print(specialName, /*isSigned:*/ intTy.isSigned());

				specialName << (intTy.isSigned() ? "_si" : "_ui");
				auto width = intTy.getWidthOrSentinel();
				if (width != -1)
				specialName << width;
			} else {
				constant.value().print(specialName, /*isSigned:*/ false);
			}
			setNameFn(constant.getResult(), specialName.str());
			}
		}

		/// Get a special name to use when printing the entry block arguments of the
		/// region contained by an operation in this dialect.
		void getAsmBlockArgumentNames(Block *block,
										OpAsmSetValueNameFn setNameFn) const override {
			// Check to see if the operation containing the arguments has 'secfir.name'
			// attributes for them.  If so, use that as the name.
			auto *parentOp = block->getParentOp();

			for (size_t i = 0, e = block->getNumArguments(); i != e; ++i) {
			// Scan for a 'secfir.name' attribute.
			if (auto str = getSecFIRNameAttr(impl::getArgAttrs(parentOp, i)))
				setNameFn(block->getArgument(i), str.getValue());
			}
		}
	};
} // end anonymous namespace

/// Constructor for the SecFIR dialect. This is the point of registration of 
/// custom types and operations for the dialect.
SecFIRDialect::SecFIRDialect(MLIRContext *context)
    	: Dialect(getDialectNamespace(), context, ::mlir::TypeID::get<SecFIRDialect>()) {


	// Register types.
  	mlir::Dialect::addTypes<SIntType, UIntType, ClockType, ResetType, AsyncResetType, AnalogType,
           // Derived Types
           FlipType, BundleType, FVectorType, ShareType, RandomnessType>();

	// Register operations.
  	mlir::Dialect::addOperations<
			#define GET_OP_LIST
			#include "SecFIR.cpp.inc"
      	>();

  	// Register interface implementations.
  	addInterfaces<SecFIROpAsmDialectInterface>();
}

SecFIRDialect::~SecFIRDialect() {}

/// Registered hook to materialize a single constant operation from a given
/// attribute value with the desired resultant type. This method should use
/// the provided builder to create the operation without changing the
/// insertion position. The generated operation is expected to be constant
/// like, i.e. single result, zero operands, non side-effecting, etc. On
/// success, this hook should return the value generated to represent the
/// constant value. Otherwise, it should return null on failure.
Operation *SecFIRDialect::materializeConstant(OpBuilder &builder,
                                              Attribute value, Type type,
                                              Location loc) {
  // Integer constants.
  if (auto intType = type.dyn_cast<IntType>())
    if (auto attrValue = value.dyn_cast<IntegerAttr>())
      return builder.create<circt::secfir::ConstantOp>(loc, type, attrValue);

  return nullptr;
}

// Provide implementations for the enums we use.
#include "SecFIREnums.cpp.inc"