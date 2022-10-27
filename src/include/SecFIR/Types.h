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

//===- SecFIR/Types.h - SecFIR dialect -------------------------*- C++ -*-===//
//
// This file defines Types for the SecFIR dialect in MLIR.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLTypes.h)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CIRCT_DIALECT_SecFIR_TYPES_H
#define CIRCT_DIALECT_SecFIR_TYPES_H

#include "SecFIR/SecFIRDialect.h"
#include "mlir/IR/Types.h"

namespace circt {
namespace secfir {

    namespace detail {
        struct WidthTypeStorage;
        struct FlipTypeStorage;
        struct BundleTypeStorage;
        struct VectorTypeStorage;
    } // namespace detail.

using namespace mlir;

    class ClockType;
    class ResetType;
    class AsyncResetType;
    class SIntType;
    class UIntType;
    class AnalogType;
    class FlipType;
    class BundleType;
    class FVectorType;

    // This is a common base class for all SecFIR types.
    class SecFIRType : public Type {
    public:
        void print(raw_ostream &os) const;

        /// Return true if this is a "passive" type - one that contains no "flip"
        /// types recursively within itself.
        bool isPassive();

        /// Return this type with any flip types recursively removed from itself.
        SecFIRType getPassiveType();

        /// Return this type with all ground types replaced with UInt<1>.  This is
        /// used for `mem` operations.
        SecFIRType getMaskType();

        /// Return this type with widths of all ground types removed. This
        /// enables two types to be compared by structure and name ignoring
        /// widths.
        SecFIRType getWidthlessType();

        /// If this is an IntType, AnalogType, or sugar type for a single bit (Clock,
        /// Reset, etc) then return the bitwidth.  Return -1 if the is one of these
        /// types but without a specified bitwidth.  Return -2 if this isn't a simple
        /// type.
        int32_t getBitWidthOrSentinel();

        /// Support method to enable LLVM-style type casting.
        static bool classof(Type type) {
            return llvm::isa<SecFIRDialect>(type.getDialect());
        }

        /// Return true if this is a valid "reset" type.
        bool isResetType();

    protected:
        using Type::Type;
    };

    //===----------------------------------------------------------------------===//
    // Ground Types Without Parameters
    //===----------------------------------------------------------------------===//

    /// `secfir.Clock` describe wires and ports meant for carrying clock signals.
    class ClockType
            : public SecFIRType::TypeBase<ClockType, SecFIRType, DefaultTypeStorage> {
    public:
        using Base::Base;
        static ClockType get(MLIRContext *context) { return Base::get(context); }
    };

    /// `secfir.Reset`.
    /// TODO(firrtl spec): This is not described in the FIRRTL spec.
    class ResetType
            : public SecFIRType::TypeBase<ResetType, SecFIRType, DefaultTypeStorage> {
    public:
        using Base::Base;
        static ResetType get(MLIRContext *context) { return Base::get(context); }
    };

    /// `secfir.AsyncReset`.
    /// TODO(firrtl spec): This is not described in the FIRRTL spec.
    class AsyncResetType 
            : public SecFIRType::TypeBase<AsyncResetType, SecFIRType, DefaultTypeStorage> {
    public:
        using Base::Base;
        static AsyncResetType get(MLIRContext *context) { return Base::get(context); }
    };

    //===----------------------------------------------------------------------===//
    // Width Qualified Ground Types
    //===----------------------------------------------------------------------===//

    template <typename ConcreteType, typename ParentType>
    class WidthQualifiedType
            : public SecFIRType::TypeBase<ConcreteType, ParentType, detail::WidthTypeStorage> {
    public:
        using SecFIRType::TypeBase<ConcreteType, ParentType,
                                    detail::WidthTypeStorage>::Base::Base;

        /// Return the width of this type, or -1 if it has none specified.
        int32_t getWidthOrSentinel() {
            auto width = static_cast<ConcreteType *>(this)->getWidth();
            return width.hasValue() ? width.getValue() : -1;
        }
    };

    class SIntType;
    class UIntType;
    class ShareType;
    class DuplicatedShareType;
    class RandomnessType;
    /// This is the common base class between SIntType and UIntType.
    class IntType : public SecFIRType {
    public:
        using SecFIRType::SecFIRType;

        /// Return a SIntType or UInt type with the specified signedness and width.
        static IntType get(MLIRContext *context, bool isSigned, int32_t width = -1);

        bool isSigned() { return isa<SIntType>(); }
        bool isUnsigned() { return isa<UIntType>(); }
        bool isShare() { return isa<ShareType>(); }
        bool isDuplicatedShare() { return isa<DuplicatedShareType>(); }
        bool isRandomness() { return isa<RandomnessType>(); }

        /// Return true if this integer type has a known width.
        bool hasWidth() { return getWidth().hasValue(); }

        /// Return the bitwidth of this type or None if unknown.
        Optional<int32_t> getWidth();

        /// Return the width of this type, or -1 if it has none specified.
        int32_t getWidthOrSentinel() {
            auto width = getWidth();
            return width.hasValue() ? width.getValue() : -1;
        }

        static bool classof(Type type) {
            return type.isa<SIntType>() || type.isa<UIntType>() || 
                    type.isa<ShareType>() || type.isa<DuplicatedShareType>() || 
                    type.isa<RandomnessType>();
        }
    };

    /// A signed integer type, whose width may not be known.
    class SIntType : public WidthQualifiedType<SIntType, IntType> {
    public:
        using WidthQualifiedType::WidthQualifiedType;

        /// Return a SIntType with a known width, or -1 for unknown.
        static SIntType get(MLIRContext *context, int32_t width = -1);

        /// Return the bitwidth of this type or None if unknown.
        Optional<int32_t> getWidth();
    };

    /// An unsigned integer type, whose width may not be known.
    class UIntType : public WidthQualifiedType<UIntType, IntType> {
    public:
        using WidthQualifiedType::WidthQualifiedType;

        /// Get an with a known width, or -1 for unknown.
        static UIntType get(MLIRContext *context, int32_t width = -1);

        /// Return the bitwidth of this type or None if unknown.
        Optional<int32_t> getWidth();
    };

    // `secfir.Analog` can be attached to multiple drivers.
    class AnalogType : public WidthQualifiedType<AnalogType, SecFIRType> {
    public:
        using WidthQualifiedType::WidthQualifiedType;

        /// Get an with a known width, or -1 for unknown.
        static AnalogType get(MLIRContext *context, int32_t width = -1);

        /// Return the bitwidth of this type or None if unknown.
        Optional<int32_t> getWidth();
    };

    //===----------------------------------------------------------------------===//
    // Flip Type
    //===----------------------------------------------------------------------===//
    class FlipType 
            :public SecFIRType::TypeBase<FlipType, SecFIRType, detail::FlipTypeStorage> {
    public:
        using Base::Base;

        SecFIRType getElementType();

        static SecFIRType get(SecFIRType element);
    };

    //===----------------------------------------------------------------------===//
    // Bundle Type
    //===----------------------------------------------------------------------===//

    /// BundleType is an aggregate of named elements.  This is effectively a struct
    /// for SecFIR.
    class BundleType : public SecFIRType::TypeBase<BundleType, SecFIRType,
                                                detail::BundleTypeStorage> {
    public:
        using Base::Base;

        // Each element of a bundle, which is a name and type.
        using BundleElement = std::pair<Identifier, SecFIRType>;

        static SecFIRType get(ArrayRef<BundleElement> elements, MLIRContext *context);

        ArrayRef<BundleElement> getElements();

        size_t getNumElements() { return getElements().size(); }

        /// Look up an element by name.  This returns None on failure.
        llvm::Optional<BundleElement> getElement(StringRef name);
        SecFIRType getElementType(StringRef name);

        /// Return true if this is a "passive" type - one that contains no "flip"
        /// types recursively within itself.
        bool isPassive();

        /// Return this type with any flip types recursively removed from itself.
        SecFIRType getPassiveType();
    };

    //===----------------------------------------------------------------------===//
    // FVector Type
    //===----------------------------------------------------------------------===//

    /// VectorType is a fixed size collection of elements, like an array.
    class FVectorType : public SecFIRType::TypeBase<FVectorType, SecFIRType,
                                                    detail::VectorTypeStorage> {
    public:
        using Base::Base;

        static SecFIRType get(SecFIRType elementType, unsigned numElements);

        SecFIRType getElementType();
        unsigned getNumElements();

        /// Return true if this is a "passive" type - one that contains no "flip"
        /// types recursively within itself.
        bool isPassive();

        /// Return this type with any flip types recursively removed from itself.
        SecFIRType getPassiveType();
    };

    //===----------------------------------------------------------------------===//
    // Share Type
    //===----------------------------------------------------------------------===//
    struct ShareTypeStorage : mlir::TypeStorage {
        ShareTypeStorage(int32_t width, int32_t shareDomain) : 
                        width(width), shareDomain(shareDomain) {}
        using KeyTy = std::pair<int32_t, int32_t>;

        bool operator==(const KeyTy &key) const { return key == KeyTy(width, shareDomain); }

        static ShareTypeStorage *construct(TypeStorageAllocator &allocator,
                                            const KeyTy &key) {
            return new (allocator.allocate<ShareTypeStorage>()) ShareTypeStorage(
                                            key.first, key.second);
        }

        static KeyTy getKey(int32_t width, int32_t shareDomain){
            return KeyTy(width, shareDomain);
        }

        LogicalResult mutate(
                StorageUniquer::StorageAllocator &allocator, 
                mlir::Value share,
                mlir::Value parallelShare
        ){
            if(parallelShareMap.count(share) == 0){
                parallelShareMap[share] = std::vector<mlir::Value>();
            }
            parallelShareMap[share].push_back(parallelShare);
            return success();
        }

        int32_t width;
        int32_t shareDomain;
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> parallelShareMap;
    };

    template <typename ConcreteType, typename ParentType>
    class ShareQualifiedType
            : public SecFIRType::TypeBase<ConcreteType, ParentType, ShareTypeStorage> {
    public:
        using SecFIRType::TypeBase<ConcreteType, ParentType,
                                    ShareTypeStorage>::Base::Base;

        /// Return the width of this type, or -1 if it has none specified.
        int32_t getWidthOrSentinel() {
            auto width = static_cast<ConcreteType *>(this)->getWidth();
            return width.hasValue() ? width.getValue() : -1;
        }

        /// Return the share domain of this type, or -2 if it has none specified.
        /// -1 is defined as randomness
        int32_t getShareDomainOrSentinel() {
            auto shareDomain = static_cast<ConcreteType *>(this)->getShareDomain();
            return shareDomain.hasValue() ? shareDomain.getValue() : -2;
        }
    };

    /// An unsigned integer type, whose width may not be known.
    class ShareType : public ShareQualifiedType<ShareType, IntType> {
    public:
        using ShareQualifiedType::ShareQualifiedType;

        /// Get an with a known width, or -1 for unknown.
        static ShareType get(MLIRContext *context, int32_t width = -1, int32_t shareDomain = -2);

        /// Function that return the bitwidth of the share type
        Optional<int32_t> getWidth();
        /// Function that return the domain ID of the share type
        Optional<int32_t> getShareDomain();

        /// Function that adds a link from one share to another share,
        /// that is in parallel in another share domain.
        ///
        /// share : the share from which the parallel share should be found
        /// parallel share : the share in another share domain
        void setParallelShare(mlir::Value share, mlir::Value parallelShare){
            LogicalResult result = Base::mutate(share, parallelShare);
            assert(succeeded(result) && "failed to add value to parallel share list");
        }

        /// Function that returns a list of parallel shares
        ///
        /// share : the share of which the parallel shares should be returned
        std::vector<mlir::Value> getParallelShares(mlir::Value share){
            return this->getImpl()->parallelShareMap[share];
        }

        /// A function that updates the list of parallel shares for a specific share,
        /// by removing one share from the list and insert another share instead.
        /// Needs to be executed whenever a operation belonging to a share is changed
        /// to another instance (e.g. cloned).
        ///
        /// share : the share that defines the list
        /// oldParallelShare : the share that is removed
        /// newParallelShare : the share that is added
        LogicalResult updateParallelShare(
                    mlir::Value share, 
                    mlir::Value oldParallelShare,
                    mlir::Value newParallelShare
        ){
            //Return failure if the share has no list of parallel shares
            if(this->getImpl()->parallelShareMap.count(share) < 1){
                return failure();
            }

            //Go through all parallel shares to find the one that should be replaced
            unsigned len = this->getImpl()->parallelShareMap[share].size();
            for(unsigned i=0; i<len; i++){
                if(this->getImpl()->parallelShareMap[share][i] == oldParallelShare){
                    this->getImpl()->parallelShareMap[share][i] = newParallelShare;
                    break;
                }
            }  
            return success();      
        }

    };

    //===----------------------------------------------------------------------===//
    // Duplicated Share Type
    //===----------------------------------------------------------------------===//
    struct DuplicatedShareTypeStorage : mlir::TypeStorage {
        DuplicatedShareTypeStorage(int32_t width, int32_t shareDomain, int32_t duplicationDomain) : 
                        width(width), shareDomain(shareDomain), duplicationDomain(duplicationDomain) {}
        using KeyTy = std::tuple<int32_t, int32_t, int32_t>;

        bool operator==(const KeyTy &key) const { return key == KeyTy(width, shareDomain, duplicationDomain); }

        static DuplicatedShareTypeStorage *construct(TypeStorageAllocator &allocator,
                                            const KeyTy &key) {
            return new (allocator.allocate<DuplicatedShareTypeStorage>()) DuplicatedShareTypeStorage(
                                            std::get<0>(key), std::get<1>(key), std::get<2>(key));
        }

        static KeyTy getKey(int32_t width, int32_t shareDomain, int32_t duplicationDomain){
            return KeyTy(width, shareDomain, duplicationDomain);
        }

        // LogicalResult mutate(
        //         StorageUniquer::StorageAllocator &allocator, 
        //         // mlir::Value share,
        //         // mlir::Value parallelShare,
        // ){
        //     // if(parallelShareMap.count(share) == 0){
        //     //     parallelShareMap[share] = std::vector<mlir::Value>();
        //     // }
        //     // parallelShareMap[share].push_back(parallelShare);
        //     return success();
        // }

        int32_t width;
        int32_t shareDomain;
        int32_t duplicationDomain;
        //mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> parallelShareMap;
    };

    template <typename ConcreteType, typename ParentType>
    class DuplicatedShareQualifiedType
            : public SecFIRType::TypeBase<ConcreteType, ParentType, DuplicatedShareTypeStorage> {
    public:
        using SecFIRType::TypeBase<ConcreteType, ParentType,
                                    DuplicatedShareTypeStorage>::Base::Base;

        /// Return the width of this type, or -1 if it has none specified.
        int32_t getWidthOrSentinel() {
            auto width = static_cast<ConcreteType *>(this)->getWidth();
            return width.hasValue() ? width.getValue() : -1;
        }

        /// Return the share domain of this type, or -2 if it has none specified.
        /// -1 is defined as randomness
        int32_t getShareDomainOrSentinel() {
            auto shareDomain = static_cast<ConcreteType *>(this)->getShareDomain();
            return shareDomain.hasValue() ? shareDomain.getValue() : -2;
        }

        /// Return the duplication domain of this type, or -1 if it has none specified.
        int32_t getDuplicationDomainOrSentinel(){
            auto duplicationDomain = static_cast<ConcreteType *>(this)->getDuplicationDomain();
            return duplicationDomain.hasValue() ? duplicationDomain.getValue() : -1;
        }
    };

    /// An unsigned integer type, whose width may not be known.
    class DuplicatedShareType : public DuplicatedShareQualifiedType<DuplicatedShareType, IntType> {
    public:
        using DuplicatedShareQualifiedType::DuplicatedShareQualifiedType;

        /// Get an with a known width, or -1 for unknown.
        static DuplicatedShareType get(MLIRContext *context, int32_t width = -1, int32_t shareDomain = -2, int32_t duplicationDomain = -1);

        /// Function that return the bitwidth of the share type
        Optional<int32_t> getWidth();
        /// Function that return the domain ID of the share type
        Optional<int32_t> getShareDomain();
        /// Function that return the domain ID of the duplication type
        Optional<int32_t> getDuplicationDomain();

    };

    //===----------------------------------------------------------------------===//
    // Randomness Type
    //===----------------------------------------------------------------------===//
    /// An unsigned integer type, whose width may not be known.
    class RandomnessType : public WidthQualifiedType<RandomnessType, IntType> {
    public:
        using WidthQualifiedType::WidthQualifiedType;

        /// Get an with a known width, or -1 for unknown.
        static RandomnessType get(MLIRContext *context, int32_t width = -1);

        /// Return the bitwidth of this type or None if unknown.
        Optional<int32_t> getWidth();
    };

} // namespace secfir
} // namespace circt

namespace llvm {

    // Type hash just like pointers.
    template <> struct DenseMapInfo<circt::secfir::SecFIRType> {
        using SecFIRType = circt::secfir::SecFIRType;

        static SecFIRType getEmptyKey() {
            auto pointer = llvm::DenseMapInfo<void *>::getEmptyKey();
            return SecFIRType(static_cast<mlir::Type::ImplType *>(pointer));
        }
        static SecFIRType getTombstoneKey() {
            auto pointer = llvm::DenseMapInfo<void *>::getTombstoneKey();
            return SecFIRType(static_cast<mlir::Type::ImplType *>(pointer));
        }
        static unsigned getHashValue(SecFIRType val) { return mlir::hash_value(val); }
        static bool isEqual(SecFIRType LHS, SecFIRType RHS) { return LHS == RHS; }
    };

} // namespace llvm

#endif // CIRCT_DIALECT_SecFIR_TYPES_H