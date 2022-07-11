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

//===- Ops.cpp - Implement the SecFIR operations --------------------------===//
//
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/lib/Dialect/FIRRTL/FIRRTLOps.cpp)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SecFIR/Ops.h"

#include "mlir/IR/Diagnostics.h"
#include "mlir/IR/DialectImplementation.h"
#include "mlir/IR/FunctionImplementation.h"
#include "mlir/IR/StandardTypes.h"
#include "llvm/ADT/DenseMap.h"

using namespace circt;
using namespace secfir;

//===----------------------------------------------------------------------===//
// CircuitOp
//===----------------------------------------------------------------------===//

void CircuitOp::build(OpBuilder &builder, OperationState &result,
                      StringAttr name) {
  // Add an attribute for the name.
  result.addAttribute(builder.getIdentifier("name"), name);

  // Create a region and a block for the body.  The argument of the region is
  // the loop induction variable.
  Region *bodyRegion = result.addRegion();
  Block *body = new Block();
  bodyRegion->push_back(body);
  CircuitOp::ensureTerminator(*bodyRegion, builder, result.location);
}

static void print(OpAsmPrinter &p, CircuitOp op) {
  p << op.getOperationName() << " ";
  p.printAttribute(op.nameAttr());

  p.printOptionalAttrDictWithKeyword(op.getAttrs(), {"name"});

  p.printRegion(op.body(),
                /*printEntryBlockArgs=*/false,
                /*printBlockTerminators=*/false);
}

static ParseResult parseCircuitOp(OpAsmParser &parser, OperationState &result) {
  // Parse the module name.
  StringAttr nameAttr;
  if (parser.parseAttribute(nameAttr, "name", result.attributes))
    return failure();

  // Parse the optional attribute list.
  if (parser.parseOptionalAttrDictWithKeyword(result.attributes))
    return failure();

  // Parse the body region.
  Region *body = result.addRegion();
  if (parser.parseRegion(*body, /*regionArgs*/ {}, /*argTypes*/ {}))
    return failure();

  CircuitOp::ensureTerminator(*body, parser.getBuilder(), result.location);
  return success();
}

static LogicalResult verifyCircuitOp(CircuitOp &circuit) {
  StringRef main = circuit.name();

  // Check that the circuit has a non-empty name.
  if (main.empty()) {
    circuit.emitOpError("must have a non-empty name");
    return failure();
  }

  // Check that a module matching the "main" module exists in the circuit.
  if (!circuit.lookupSymbol(main)) {
    circuit.emitOpError("must contain one module that matches main name '" +
                        main + "'");
    return failure();
  }
  return success();
}

Region &CircuitOp::getBodyRegion() { return getOperation()->getRegion(0); }
Block *CircuitOp::getBody() { return &getBodyRegion().front(); }

//===----------------------------------------------------------------------===//
// My ModuleOp
//===----------------------------------------------------------------------===//

static void buildMyModule(OpBuilder &builder, OperationState &result, 
                          StringAttr name, const ArrayRef<ModulePortInfo> ports){
  //Add name of module to the symbol table
  result.addAttribute(mlir::SymbolTable::getSymbolAttrName(), name);
  //Identify inputs and outputs
  SmallVector<mlir::Attribute, 4> argNames, resultNames;
  SmallVector<mlir::Type, 4> argTypes, resultTypes;
  SmallString<8> attrNameBuf;
  unsigned i = 0;
  for(auto port : ports){
    if(port.isInput()){
      argNames.push_back(port.name);
      argTypes.push_back(port.type);
    } else if(port.isOutput()){
      resultNames.push_back(port.name);
      resultTypes.push_back(port.type);
    }

    auto namedAttr =NamedAttribute(builder.getIdentifier("secfir.name"), port.name);
    result.addAttribute(mlir::impl::getArgAttrName(i, attrNameBuf), builder.getDictionaryAttr(namedAttr));
    i++;
  }

  //Create a function-like operation
  mlir::FunctionType type = builder.getFunctionType(argTypes, resultTypes);
  //Add the attributes for types, input names, and ouput names
  result.addAttribute(mlir::impl::getTypeAttrName(), TypeAttr::get(type));
  result.addAttribute("argNames", builder.getArrayAttr(argNames));
  result.addAttribute("resultNames", builder.getArrayAttr(resultNames));
  //Add a region to the module
  result.addRegion();
}

/// Builder function for the module operation
void secfir::ModuleOp::build(OpBuilder &builder, OperationState &result,
                     StringAttr name, const ArrayRef<ModulePortInfo> ports){
  //Build a module operation
  buildMyModule(builder, result, name, ports);
  //Get the region from the operation state
  mlir::Region *bodyRegion = result.regions[0].get();
  //Create a region and a block for the body
  mlir::Block *body = new mlir::Block();
  bodyRegion->push_back(body);
  //Add arguments to the body
  for(auto port : ports){
    if(port.isInput()) body->addArgument(port.type);
  }
  secfir::ModuleOp::ensureTerminator(*bodyRegion, builder, result.location);
}

static void printMyModuleOp(OpAsmPrinter &p, Operation *op){

  auto typeAttr = op->getAttrOfType<TypeAttr>(secfir::ModuleOp::getTypeAttrName());
  mlir::FunctionType fnType = typeAttr.getValue().cast<FunctionType>();

  //Region &body = op->getRegion(0);

  auto argNames = op->getAttrOfType<ArrayAttr>("argNames");
  auto resultNames = op->getAttrOfType<ArrayAttr>("resultNames");
  auto argTypes = fnType.getInputs();
  auto resultTypes = fnType.getResults();

  //Print name
  p << ' ';
  p.printSymbolName(SymbolTable::getSymbolName(op));
  //Print Inputs
  p << '(';
  for(size_t i=0; i < argTypes.size(); i++){
    if(i != 0) p << ", ";
    auto argName = argNames[i].cast<StringAttr>().getValue();
    if(!argName.empty())  p << '%' << argName << ": ";
    p.printType(argTypes[i]);
    //p.printOptionalAttrDict(getArgAttrs(op,i));
  }
  p << ')';
  //Print outputs
  if(!resultTypes.empty()){
    p << "\n\t -> (";
    for(size_t i=0; i<resultTypes.size(); i++){
      if(i != 0) p << ", ";
      auto resultName = resultNames[i].cast<StringAttr>().getValue();
      if(!resultName.empty()) p << '%' << resultName << ": ";
      p.printType(resultTypes[i]);
    }
    p << ')';
  }
  //Print attributes
  SmallString<8> attrNameBuf[argNames.size()+resultNames.size()];
  SmallVector<StringRef, 4> omittedAttrs;
  for(size_t i=0; i<argNames.size()+resultNames.size(); i++){
    omittedAttrs.push_back(mlir::impl::getArgAttrName(i, attrNameBuf[i]));
  }
  omittedAttrs.push_back("sym_name");
  omittedAttrs.push_back("argNames");
  omittedAttrs.push_back("resultNames");
  omittedAttrs.push_back("type");
  p.printOptionalAttrDictWithKeyword(op->getAttrs(), omittedAttrs);
}

static void print(OpAsmPrinter &p, secfir::ModuleOp op) {
  printMyModuleOp(p, op);

  // Print the body if this is not an external function.
  Region &body = op.getBody();
  if (!body.empty())
    p.printRegion(body, /*printEntryBlockArgs=*/false,
                  /*printBlockTerminators=*/true);
}

//===----------------------------------------------------------------------===//
// FExtModuleOp and FModuleOp
//===----------------------------------------------------------------------===//

FunctionType secfir::getModuleType(Operation *op) {
  auto typeAttr = op->getAttrOfType<TypeAttr>(ModuleOp::getTypeAttrName());
  return typeAttr.getValue().cast<FunctionType>();
}

/// This function can extract information about ports from a module and an
/// extmodule.
void secfir::getModulePortInfo(Operation *op,
                               SmallVectorImpl<ModulePortInfo> &results) {
  auto argTypes = getModuleType(op).getInputs();

  for (unsigned i = 0, e = argTypes.size(); i < e; ++i) {
    auto argAttrs = ::mlir::impl::getArgAttrs(op, i);
    auto type = argTypes[i].dyn_cast<SecFIRType>();

    // Convert IntegerType ports to IntType ports transparently.
    if (!type) {
      auto intType = argTypes[i].cast<IntegerType>();
      type = IntType::get(op->getContext(), intType.isSigned(),
                          intType.getWidth());
    }

    results.push_back({getSecFIRNameAttr(argAttrs), type});
  }
}

static LogicalResult verifyConstantOp(ConstantOp constant) {
  // If the result type has a bitwidth, then the attribute must match its width.
  auto intType = constant.getType().cast<IntType>();
  auto width = intType.getWidthOrSentinel();
  if (width != -1 && (int)constant.value().getBitWidth() != width)
    return constant.emitError(
        "secfir.constant attribute bitwidth doesn't match return type");

  return success();
}

/// Build a ConstantOp from an APInt and a SecFIR type, handling the attribute
/// formation for the 'value' attribute.
void ConstantOp::build(OpBuilder &builder, OperationState &result, IntType type,
                       const APInt &value) {

  int32_t width = type.getWidthOrSentinel();
  assert((width == -1 || (int32_t)value.getBitWidth() == width) &&
         "incorrect attribute bitwidth for secfir.constant");

  auto signedness =
      type.isSigned() ? IntegerType::Signed : IntegerType::Unsigned;
  Type attrType =
      IntegerType::get(value.getBitWidth(), signedness, type.getContext());
  auto attr = builder.getIntegerAttr(attrType, value);
  return build(builder, result, type, attr);
}

//===----------------------------------------------------------------------===//
// Binary Primitives
//===----------------------------------------------------------------------===//

/// If LHS and RHS are both UInt or SInt types, the return true and compute the
/// max width of them if known.  If unknown, return -1 in maxWidth.
static bool isSameIntegerType(SecFIRType lhs, SecFIRType rhs,
                              int32_t &maxWidth) {
  // Must have two integer types with the same signedness.
  auto lhsi = lhs.dyn_cast<IntType>();
  if (!lhsi || lhsi.getTypeID() != rhs.getTypeID())
    return false;

  auto lhsWidth = lhsi.getWidth();
  auto rhsWidth = rhs.cast<IntType>().getWidth();
  if (lhsWidth.hasValue() && rhsWidth.hasValue())
    maxWidth = std::max(lhsWidth.getValue(), rhsWidth.getValue());
  else
    maxWidth = -1;
  return true;
}


// //===----------------------------------------------------------------------===//
// // Unary Primitives
// //===----------------------------------------------------------------------===//

SecFIRType secfir::getNotResult(SecFIRType input) {
  auto inputi = input.dyn_cast<IntType>();
  if (!inputi)
    return {};
  return UIntType::get(input.getContext(), inputi.getWidthOrSentinel());
}

//===----------------------------------------------------------------------===//
// Side-Channel Gadget Operations
//===----------------------------------------------------------------------===//
SecFIRType secfir::getRefreshResult(SecFIRType input) {
  auto inputi = input.dyn_cast<IntType>();
  if (!inputi)
    return {};
  return UIntType::get(input.getContext(), inputi.getWidthOrSentinel());
}

//-------------------------------------------------------------------------------
// Other Operations
//-------------------------------------------------------------------------------

void CombLogicOp::build(
        OpBuilder &builder, 
        OperationState &odsState, 
        TypeRange resultTypes,
        ValueRange operands
        //ArrayRef<NamedAttribute> attributes = {}
){

  odsState.addOperands(operands);
  //odsState.addAttributes(attributes);
  (void)odsState.addRegion();
  odsState.addTypes(resultTypes);

  // Create a region and a block for the body.
  auto *bodyRegion = odsState.regions[0].get();
  Block *body = new Block();
  bodyRegion->push_back(body);

  // Add arguments to the body block.
   for (auto elt : operands)
     body->addArgument(elt.getType());

}
//===----------------------------------------------------------------------===//
// TblGen Generated Logic.
//===----------------------------------------------------------------------===//

// Provide the autogenerated implementation guts for the Op classes.
#define GET_OP_CLASSES
#include "SecFIR.cpp.inc"
