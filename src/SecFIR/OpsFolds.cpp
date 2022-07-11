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

//===- OpFolds.cpp - Implement folds and canonicalizations for ops --------===//
//
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/lib/Dialect/FIRRTL/FIRRTLFolds.cpp)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SecFIR/Ops.h"

#include "mlir/Dialect/CommonFolders.h"
#include "mlir/IR/Matchers.h"
#include "mlir/IR/PatternMatch.h"

using namespace circt;
using namespace secfir;

static Attribute getIntAttr(const APInt &value, MLIRContext *context) {
  return IntegerAttr::get(IntegerType::get(value.getBitWidth(), context),
                          value);
}

namespace {
struct ConstantIntMatcher {
  APInt &value;
  ConstantIntMatcher(APInt &value) : value(value) {}
  bool match(Operation *op) {
    if (auto cst = dyn_cast<ConstantOp>(op)) {
      value = cst.value();
      return true;
    }
    return false;
  }
};
} // end anonymous namespace

static inline ConstantIntMatcher m_FConstant(APInt &value) {
  return ConstantIntMatcher(value);
}

//===----------------------------------------------------------------------===//
// Fold Hooks
//===----------------------------------------------------------------------===//

OpFoldResult ConstantOp::fold(ArrayRef<Attribute> operands) {
  assert(operands.empty() && "constant has no operands");
  return valueAttr();
}

// TODO: Move to DRR.
OpFoldResult AndPrimOp::fold(ArrayRef<Attribute> operands) {
  APInt value;

  /// and(x, 0) -> 0
  if (matchPattern(rhs(), m_FConstant(value)) && value.isNullValue() &&
      rhs().getType() == getType())
    return rhs();

  /// and(x, -1) -> x
  if (matchPattern(rhs(), m_FConstant(value)) && value.isAllOnesValue() &&
      lhs().getType() == getType() && rhs().getType() == getType())
    return lhs();

  /// and(x, x) -> x
  if (lhs() == rhs() && rhs().getType() == getType())
    return rhs();

  return constFoldBinaryOp<IntegerAttr>(operands,
                                        [](APInt a, APInt b) { return a & b; });
}

OpFoldResult OrPrimOp::fold(ArrayRef<Attribute> operands) {
  APInt value;

  /// or(x, 0) -> x
  if (matchPattern(rhs(), m_FConstant(value)) && value.isNullValue() &&
      lhs().getType() == getType())
    return lhs();

  /// or(x, -1) -> -1
  if (matchPattern(rhs(), m_FConstant(value)) && value.isAllOnesValue() &&
      rhs().getType() == getType() && lhs().getType() == getType())
    return rhs();

  /// or(x, x) -> x
  if (lhs() == rhs())
    return rhs();

  return constFoldBinaryOp<IntegerAttr>(operands,
                                        [](APInt a, APInt b) { return a | b; });
}

OpFoldResult XorPrimOp::fold(ArrayRef<Attribute> operands) {
  APInt value;

  /// xor(x, 0) -> x
  if (matchPattern(rhs(), m_FConstant(value)) && value.isNullValue() &&
      lhs().getType() == getType())
    return lhs();

  /// xor(x, x) -> 0
  if (lhs() == rhs()) {
    auto width = getType().cast<IntType>().getWidthOrSentinel();
    if (width == -1)
      width = 1;
    auto type = IntegerType::get(width, getContext());
    return Builder(getContext()).getZeroAttr(type);
  }

  return constFoldBinaryOp<IntegerAttr>(operands,
                                        [](APInt a, APInt b) { return a ^ b; });
}
