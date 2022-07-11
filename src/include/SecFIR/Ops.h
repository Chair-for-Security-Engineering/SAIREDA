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

//===- SecFIR/Ops.h - Declare SecFIR dialect operations ---------*- C++ -*-===//
//
// This file declares the operation class for the SecFIR IR.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLOps.h)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CIRCT_DIALECT_SecFIR_OPS_H
#define CIRCT_DIALECT_SecFIR_OPS_H

#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Types.h"

#include "mlir/IR/Builders.h"
#include "mlir/IR/FunctionSupport.h"
#include "mlir/IR/RegionKindInterface.h"
#include "mlir/IR/SymbolTable.h"
#include "mlir/Interfaces/SideEffectInterfaces.h"
#include "mlir/Interfaces/ControlFlowInterfaces.h"

namespace circt {
namespace secfir {

  SecFIRType getBitwiseBinaryResult(SecFIRType lhs, SecFIRType rhs);
  SecFIRType getNotResult(SecFIRType input);
  // Side-Channel Ops
  SecFIRType getRefreshResult(SecFIRType input);

  /// This holds the name and type that describes the module's ports.
  struct ModulePortInfo {
    mlir::StringAttr name;
    SecFIRType type;

    llvm::StringRef getName() const { return name ? name.getValue() : ""; }

    /// Return true if this is a simple output-only port.
    bool isOutput() { return type.isa<FlipType>(); }

    /// Return true if this is a simple input-only port.
    bool isInput() { return type.isPassive(); }

    /// Return true if this is an inout port.
    bool isInOut() { return !isOutput() && !isInput(); }
  };

  /// Return the function type that corresponds to a module.
  FunctionType getModuleType(mlir::Operation *op);

  /// This function can extract information about ports from a module and an
  /// extmodule.
  void getModulePortInfo(mlir::Operation *op, llvm::SmallVectorImpl<ModulePortInfo> &results);

} // namespace firrtl
} // namespace circt

#define GET_OP_CLASSES
#include "SecFIR.h.inc"

#endif // CIRCT_DIALECT_SecFIR_OPS_H
