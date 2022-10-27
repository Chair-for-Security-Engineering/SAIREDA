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

//===- Types.td - SecFIR Types Definition ------------------*- tablegen -*-===//
//
// This file defines Types for the SecFIR dialect in MLIR.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLTypes.td)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// SecFIR Types Definitions
//===----------------------------------------------------------------------===//

def SecFIRType : Type<CPred<"$_self.isa<SecFIRType>()">, "SecFIRType">;

def ClockType : Type<CPred<"$_self.isa<ClockType>()">, "clock">,
                BuildableType<"ClockType::get($_builder.getContext())">;

def IntType : Type<CPred<"$_self.isa<IntType>()">, "sint or uint type">;
def SIntType : Type<CPred<"$_self.isa<SIntType>()">, "sint type">;
def UIntType : Type<CPred<"$_self.isa<UIntType>()">, "uint type">;
def ShareType : Type<CPred<"$_self.isa<ShareType>()">, "share type">;
def DuplicatedShareType : Type<CPred<"$_self.isa<DuplicatedShareType>()">, "duplicated share type">;
def AnalogType : Type<CPred<"$_self.isa<AnalogType>()">, "analog type">;

def UInt1Type : Type<CPred<"$_self.isa<UIntType>() && "
                           "$_self.cast<UIntType>().getWidth() == 1">,
                           "UInt<1>">,
                BuildableType<"UIntType::get($_builder.getContext(), 1)">;

def OneBitType : Type<CPred<"($_self.isa<IntType>() && "
                            "$_self.cast<IntType>().getWidth() == 1) ||"
                            "($_self.isa<AnalogType>() && "
                            "$_self.cast<AnalogType>().getWidth() == 1)">,
                            "UInt<1>, SInt<1>, or Analog<1>">;

def AsyncResetType : Type<CPred<"$_self.isa<AsyncResetType>()">, "AsyncReset">;

def ResetType : Type<CPred<"$_self.isa<SecFIRType>() && "
                           "$_self.cast<SecFIRType>().isResetType()">,
                    "Reset, AsyncReset, or UInt<1>">;

def PassiveType : Type<CPred<"$_self.isa<SecFIRType>() && "
                             "$_self.cast<SecFIRType>().isPassive()">,
                       "a passive type (contain no flips)">;

def UIntSIntClockType : AnyTypeOf<[SIntType, UIntType, ClockType],
                                  "sint, uint, or clock">;

def OneBitCastableType : AnyTypeOf<
  [OneBitType, ResetType, AsyncResetType, ClockType],
  "1-bit uint/sint/analog, reset, asyncreset, or clock">;

//===----------------------------------------------------------------------===//
// SecFIR Enum Definitions
//===----------------------------------------------------------------------===//

/// RUWAttr: Undefined/Old/New.
def SecFIRRUW_Undefined: I32EnumAttrCase<"Undefined", 0>;
def SecFIRRUW_Old: I32EnumAttrCase<"Old", 1>;
def SecFIRRUW_New: I32EnumAttrCase<"New", 2>;

def SecFIRRUWAttr: I32EnumAttr<"SecFIRRUWAttr", "Read Under Write Enum",
                         [SecFIRRUW_Undefined, SecFIRRUW_Old, SecFIRRUW_New]>;

def SecFIRMemDir_Infer    : I32EnumAttrCase<"Infer", 0>;
def SecFIRMemDir_Read     : I32EnumAttrCase<"Read", 1>;
def SecFIRMemDir_Write    : I32EnumAttrCase<"Write", 2>;
def SecFIRMemDir_ReadWrite: I32EnumAttrCase<"ReadWrite", 3>;

def SecFIRMemDirAttr: I32EnumAttr<"SecFIRMemDirAttr", "Memory Direction Enum",
                            [SecFIRMemDir_Infer, SecFIRMemDir_Read, SecFIRMemDir_Write,
                              SecFIRMemDir_ReadWrite]>;
