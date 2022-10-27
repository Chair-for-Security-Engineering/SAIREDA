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

#include "Conversion/SecFIRToFIRRTL.h"

using namespace circt;

namespace circt{
namespace secfir{

///--Type Converter------------------------------------------------------------
    struct SecFIRToFIRRTLTypeConverter : public mlir::TypeConverter{
            SecFIRToFIRRTLTypeConverter() {addConversion(convertType);}

        static firrtl::FIRRTLType convertType(mlir::Type type) {
            mlir::MLIRContext *ctx = type.getContext();
            // Handle clock type
            if (type.isa<secfir::ClockType>())
                return firrtl::ClockType::get(ctx);
            // Handle reset type
            else if(type.isa<secfir::ResetType>())
                return firrtl::ResetType::get(ctx);
            //Handle asynchoneos reset
            else if(type.isa<secfir::AsyncResetType>())
                return firrtl::AsyncResetType::get(ctx);
            // Handle signed integer
            else if(type.isa<secfir::SIntType>()){
                auto width = type.dyn_cast<secfir::SIntType>().getBitWidthOrSentinel();
                return firrtl::SIntType::get(ctx, width);
            // Handle unsigned integer
            } else if(type.isa<secfir::UIntType>()){
                auto width = type.dyn_cast<secfir::UIntType>().getBitWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            } else if(type.isa<secfir::ShareType>()){
                auto width = type.dyn_cast<secfir::ShareType>().getWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            } else if(type.isa<secfir::RandomnessType>()){
                auto width = type.dyn_cast<secfir::RandomnessType>().getWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            } else if(type.isa<secfir::DuplicatedShareType>()){
                auto width = type.dyn_cast<secfir::DuplicatedShareType>().getWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            //Handle analog type
            } else if(type.isa<secfir::AnalogType>()){
                auto width = type.dyn_cast<secfir::AnalogType>().getBitWidthOrSentinel();
                return firrtl::AnalogType::get(ctx, width);
            //Handle all flip types
            } else if(type.isa<secfir::FlipType>()){
                auto flipType = type.dyn_cast<secfir::FlipType>();
                //Flipped signed integer
                if(flipType.getElementType().isa<secfir::SIntType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::SIntType>().getBitWidthOrSentinel();
                    auto internType = firrtl::SIntType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                //Flipped unsigned integer
                } else if(flipType.getElementType().isa<secfir::UIntType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::UIntType>().getBitWidthOrSentinel();
                    auto internType = firrtl::UIntType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                //Flipped analog type
                } else if (flipType.getElementType().isa<secfir::AnalogType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::AnalogType>().getBitWidthOrSentinel();
                    auto internType = firrtl::AnalogType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                //Flippend share type
                } else if(flipType.getElementType().isa<secfir::ShareType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::ShareType>().getWidthOrSentinel();
                    auto internType = firrtl::UIntType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                } else if(flipType.getElementType().isa<secfir::DuplicatedShareType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::DuplicatedShareType>().getWidthOrSentinel();
                    auto internType = firrtl::UIntType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                //Flipped randomness type
                } else if(flipType.getElementType().isa<secfir::RandomnessType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            secfir::RandomnessType>().getWidthOrSentinel();
                    auto internType = firrtl::UIntType::get(ctx, width);
                    return firrtl::FlipType::get(internType);
                }
            }
            return nullptr;
        }

        ///Converter from SecFIR IntType to FIRRTL IntType
        ///(Required for conversation of ConstantOp)
        static firrtl::IntType convertIntType(mlir::Type type){
            mlir::MLIRContext *ctx = type.getContext();
            if(type.isa<secfir::SIntType>()){
                auto width = type.dyn_cast<secfir::SIntType>().getBitWidthOrSentinel();
                return firrtl::SIntType::get(ctx, width);
            // Handle unsigned integer
            } else if(type.isa<secfir::UIntType>()){
                auto width = type.dyn_cast<secfir::UIntType>().getBitWidthOrSentinel();;
                return firrtl::UIntType::get(ctx, width);
            } else if(type.isa<secfir::ShareType>()){
                auto width = type.dyn_cast<secfir::ShareType>().getWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            } else if(type.isa<secfir::RandomnessType>()){
                auto width = type.dyn_cast<secfir::RandomnessType>().getWidthOrSentinel();
                return firrtl::UIntType::get(ctx, width);
            }
        }

        static bool isFIRRTLType(mlir::Type type){
            bool returnValue = false;
            if(type.isa<firrtl::FIRRTLType>()){
                returnValue = true;
            }
            return returnValue;
        }

    };
}
}

///--Structural Operations-----------------------------------------------------

/// Conversation pattern from SecFIR circuits to FIRRTL circuits.
/// This is a one-to-one replacement conversation.
struct SecFIRCircuitOpConversion : public mlir::OpConversionPattern<secfir::CircuitOp> {
    using mlir::OpConversionPattern<secfir::CircuitOp>::OpConversionPattern;

    ///Translates a secfir.CircuitOp to a firrtl.CircuitOp
    mlir::LogicalResult matchAndRewrite(
            secfir::CircuitOp secfirCircuitOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        //Create a FIRRTL circuit operation with the same name as the SecFIR circuit operation    
        firrtl::CircuitOp firrtlCircuitOp = rewriter.create<firrtl::CircuitOp>(
                secfirCircuitOp.getLoc(), rewriter.getStringAttr(secfirCircuitOp.name()));
        
        //Insert content of secfir.CircuitOp into the new firrtl.CircuitOp
        rewriter.mergeBlockBefore(secfirCircuitOp.getBody(), 
                    &firrtlCircuitOp.getBody()->getOperations().front());
        //Clone block back to old operation to prevent circuit form being empty
        //mlir::BlockAndValueMapping mapper;
        //firrtlCircuitOp.body().cloneInto(&secfirCircuitOp.getRegion(), mapper);
        //Remove secfir.doneOp of the old secfir.CircuitOp
        bool removed = false;
        for(mlir::Operation &op : firrtlCircuitOp.getBody()->getOperations()){
            if(secfir::dyn_cast<secfir::DoneOp>(op)){
                rewriter.eraseOp(&op);
                removed = true;
            }
        }
        assert(removed && "No corresponding secfir.DoneOp for the circuit found!");

        //Delete old secfir.CircuitOp
        rewriter.eraseOp(secfirCircuitOp);     
        return mlir::success();
  }

};

/// Conversation pattern from SecFIR modules to FIRRTL modules.
/// This is a one-to-one replacement conversation.
struct SecFIRFMyModuleOpConversion : public mlir::OpConversionPattern<secfir::ModuleOp> {
    using mlir::OpConversionPattern<secfir::ModuleOp>::OpConversionPattern;

    ///Translates secfir.ModuleOp to firrtl.FModuleOp
    mlir::LogicalResult matchAndRewrite(
            secfir::ModuleOp secfirModule, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        //Create a type converter from SecFIR to FIRRTL types
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Convert types of input/output ports of the SecFIR module
        llvm::SmallVector<firrtl::ModulePortInfo, 4> firrtlPorts;
        llvm::SmallVector<secfir::ModulePortInfo, 4> secfirPorts;
        //Retrive port informations form the original SecFIR module
        secfirModule.getPortInfo(secfirPorts);
        //Do the actual conversion for all input ports
        for(secfir::ModulePortInfo secfirPort : secfirPorts){ 
            firrtl::FIRRTLType firrtlPortType = converter.convertType(secfirPort.type);
            firrtlPorts.push_back({secfirPort.name, firrtlPortType});
        }
        //Do the actual conversion for all output ports
        auto typeAttr = secfirModule.getAttrOfType<mlir::TypeAttr>(
                    secfir::ModuleOp::getTypeAttrName());
        mlir::FunctionType fnType = typeAttr.getValue().cast<mlir::FunctionType>();
        auto resultNames = secfirModule.getAttrOfType<mlir::ArrayAttr>("resultNames");
        auto resultTypes = fnType.getResults();
        for(size_t i=0; i<fnType.getResults().size(); i++){
            firrtl::FIRRTLType firrtlPortType = converter.convertType(resultTypes[i]);
            firrtlPorts.push_back({resultNames[i].cast<mlir::StringAttr>(), firrtlPortType});
        }

        //Create a new FIRRTL module with the new port types
        rewriter.setInsertionPointAfter(secfirModule);
        firrtl::FModuleOp firrtlModule = rewriter.create<firrtl::FModuleOp>(
                secfirModule.getLoc(), rewriter.getStringAttr(secfirModule.getName()), 
                firrtlPorts);
        //Add the outputs to the secfir block to transfer the block to the firrtl module
        for(size_t i=secfirPorts.size(); i<secfirPorts.size()+fnType.getResults().size(); i++){
            secfirModule.getBody().addArgument(firrtlModule.getArguments()[i].getType());
        }
        //Move body of the original secfir.module to the new firrtl.module
        rewriter.inlineRegionBefore(secfirModule.getBody(), firrtlModule.getBody(), 
                    firrtlModule.getBody().begin());
        //Erase automatic generated block of firrtl.FModuleOp
        rewriter.eraseBlock(&firrtlModule.getBlocks().back());

        //Tranfrom the secfir.OutputOp to multiple firrtl.ConnectOps (for each output one)
        for(mlir::Operation &op : firrtlModule.getBodyBlock()->getOperations()){
            if(auto outputOp = secfir::dyn_cast<secfir::OutputOp>(op)){
                rewriter.setInsertionPointAfter(&op);
                for(size_t i=0; i<outputOp.getOperands().size(); i++){
                    //Create the connect operations connection the values
                    //used in the output operation to the corresponding output
                    auto newOp = rewriter.create<firrtl::ConnectOp>(
                        op.getLoc(),
                        firrtlModule.getArguments()[secfirPorts.size()+i],
                        outputOp.getOperands()[i]
                    );
                }
                //Create a terminator for the firrtl module
                rewriter.create<firrtl::DoneOp>(op.getLoc());
                //Erase the terminator of the secfir module
                rewriter.eraseOp(outputOp);
            }
        }
        //Erase old secfir.ModuleOp
        rewriter.eraseOp(secfirModule);
        return mlir::success();
    }

};

/// Conversation pattern from SecFIR instance operation to FIRRTL instance operation.
/// This also inserts the related subfield access and connect operations.
struct SecFIRInstanceOpConversion : public mlir::OpConversionPattern<secfir::InstanceOp>{
    using mlir::OpConversionPattern<secfir::InstanceOp>::OpConversionPattern;

    mlir::LogicalResult matchAndRewrite(
            secfir::InstanceOp secfirInstanceOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        llvm::SmallVector<firrtl::BundleType::BundleElement, 3> elements;
        llvm::SmallVector<secfir::ModulePortInfo, 2> portsIn;
        llvm::SmallVector<secfir::ModulePortInfo, 2> portsOut;

        mlir::Operation *m;
        //Get the referenced module operation (as mlir::Operation)
        if(secfir::isa<firrtl::CircuitOp>(secfirInstanceOp.getParentOp()->getParentOp())){   
            auto circuit = firrtl::dyn_cast<firrtl::CircuitOp>(secfirInstanceOp.getParentOp()->getParentOp());
            m = circuit.lookupSymbol(secfirInstanceOp.moduleName());
        } //TODO: Handle secfir::CircuitOp case
        //Get module (as secfir::Module)
        //TODO: Handle firrtl::FModuleOp case
        auto module = secfir::dyn_cast<secfir::ModuleOp>(m);
        //Get the name of the module
        mlir::StringRef name = module.getName();
        //Get the name of the instance of the module
        mlir::StringAttr instanceName = rewriter.getStringAttr(
                        secfirInstanceOp.instanceName().str());
        //Get input and output ports
        module.getPortInfo(portsIn);
        module.getOutputPortInfo(portsOut);
        //Add ports to a list of bundle elements first all inputs 
        //than all outputs
        for(auto port : portsIn){
            //Get the identifier of the port
            auto argId = rewriter.getIdentifier(port.getName());
            //Get the firrtl type of the port
            mlir::Type type;
            if(!converter.isFIRRTLType(port.type)){
                type = converter.convertType(port.type);
            }else{
                type = port.type;
            }
            auto argType = firrtl::FlipType::get(type.cast<firrtl::FIRRTLType>());
            //Push port as bundle element to the list
            elements.push_back(firrtl::BundleType::BundleElement(argId, argType));
        }
        for(auto port : portsOut){
            //Get identifier of the port
            auto argId = rewriter.getIdentifier(port.getName());
            //Get the firrtl type of the port
            mlir::Type type;
            if(!converter.isFIRRTLType(port.type)){
                type = converter.convertType(port.type);
            }else{
                type = port.type;
            }
            auto argType = firrtl::FlipType::get(type.cast<firrtl::FIRRTLType>());
            //Push port as bundle element to the list
            elements.push_back(firrtl::BundleType::BundleElement(argId, argType));
        }
        //Get a bundle with all the ports to the module
        auto instType = firrtl::BundleType::get(elements, rewriter.getContext());
        //Create a type range of all the results
        mlir::TypeRange typeRange(secfirInstanceOp.getResults());

        //Create a firrtl instance operation
        firrtl::InstanceOp firrtlInstanceOp = rewriter.create<firrtl::InstanceOp>(
                    secfirInstanceOp.getLoc(),
                    instType,
                    name,
                    instanceName);
        //Connect all the inputs
        unsigned operandId = 0;        
        for(auto port : portsIn){
            //Create an operation that accesses the value in the bundle
            firrtl::SubfieldOp subfield = rewriter.create<firrtl::SubfieldOp>(
                    secfirInstanceOp.getLoc(),
                    port.type,
                    firrtlInstanceOp.getResult(),
                    port.name);
            //Connect the input to the access to the bundle
            rewriter.create<firrtl::ConnectOp>(
                    secfirInstanceOp.getLoc(),
                    subfield.getResult(),
                    secfirInstanceOp.getOperand(operandId));
            //Increase the operand index
            operandId++;
        }
        //Connect all the outputs
        unsigned resId=0;
        for(auto port : portsOut){
            //Create an operation that accesses the value in the bundle
            firrtl::SubfieldOp res = rewriter.create<firrtl::SubfieldOp>(
                    secfirInstanceOp.getLoc(),
                    port.type,
                    firrtlInstanceOp.getResult(),
                    port.name);
            //Use the output of the access operation wherever the result
            //was used befor
            secfirInstanceOp.getResult(resId).replaceAllUsesWith(res);
            //Increase the index of the result
            resId++;
        }
        //Erase the original secfir instance operation
        rewriter.eraseOp(secfirInstanceOp);
        return mlir::success();
    }
};


///--Binary Expression Operations----------------------------------------------

/// Conversation pattern from SecFIR AND operation to FIRRTL AND operation.
/// This is a one-to-one replacement conversation.
struct SecFIRAndPrimOpConversion : public mlir::OpConversionPattern<secfir::AndPrimOp> {
    using mlir::OpConversionPattern<secfir::AndPrimOp>::OpConversionPattern;

    /// Translates secfir.AndPrimOp to firrtl.AndPrimOp
    mlir::LogicalResult matchAndRewrite(
            secfir::AndPrimOp secfirAndOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a firrtl type
        if(!converter.isFIRRTLType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isFIRRTLType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Convert result type if necessary
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirAndOp.getType())){
            resType = converter.convertType(secfirAndOp.getType());
        }else{
            resType = secfirAndOp.getType();
        }
        //Replace old secfir operation with new firrtl operation
        rewriter.replaceOpWithNewOp<firrtl::AndPrimOp>(secfirAndOp, 
                resType, lhs, rhs);
        return mlir::success();
    }
};
/// Conversation pattern from SecFIR OR operation to FIRRTL OR operation.
/// This is a one-to-one replacement conversation.
struct SecFIROrPrimOpConversion : public mlir::OpConversionPattern<secfir::OrPrimOp> {
    using mlir::OpConversionPattern<secfir::OrPrimOp>::OpConversionPattern;

    /// Translates secfir.OrPrimOp to firrtl.OrPrimOp
    mlir::LogicalResult matchAndRewrite(
            secfir::OrPrimOp secfirOrOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a firrtl type
        if(!converter.isFIRRTLType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isFIRRTLType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Convert result type if necessary
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirOrOp.getType())){
            resType = converter.convertType(secfirOrOp.getType());
        }else{
            resType = secfirOrOp.getType();
        }
        //Replace old secfir operation with new firrtl operation
        rewriter.replaceOpWithNewOp<firrtl::OrPrimOp>(secfirOrOp, 
                resType, lhs, rhs);
        return mlir::success();
    }
};
/// Conversation pattern from SecFIR XOR operation to FIRRTL XOR operation.
/// This is a one-to-one replacement conversation.
struct SecFIRXorPrimOpConversion : public mlir::OpConversionPattern<secfir::XorPrimOp> {
    using mlir::OpConversionPattern<secfir::XorPrimOp>::OpConversionPattern;

    /// Translates secfir.XorPrimOp to firrtl.XorPrimOp
    mlir::LogicalResult matchAndRewrite(
            secfir::XorPrimOp secfirXorOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a firrtl type
        if(!converter.isFIRRTLType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isFIRRTLType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Convert result type if necessary
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirXorOp.getType())){
            resType = converter.convertType(secfirXorOp.getType());
        }else{
            resType = secfirXorOp.getType();
        }
        //Replace old secfir operation with new firrtl operation
        rewriter.replaceOpWithNewOp<firrtl::XorPrimOp>(secfirXorOp, 
                resType, lhs, rhs);
        return mlir::success();
    }
};

/// Conversation pattern from SecFIR MUX operation to FIRRTL MUX operation.
/// This is a one-to-one replacement conversation.
struct SecFIRMuxPrimOpConversion : public mlir::OpConversionPattern<secfir::MuxPrimOp> {
    using mlir::OpConversionPattern<secfir::MuxPrimOp>::OpConversionPattern;

    /// Translates secfir.MuxPrimOp to firrtl.MuxPrimOp
    mlir::LogicalResult matchAndRewrite(
            secfir::MuxPrimOp secfirMuxOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Get operands
        mlir::Value sel = operands[0];
        mlir::Value lhs = operands[1];
        mlir::Value rhs = operands[2];
        //Convert operand types if not already a firrtl type
        if(!converter.isFIRRTLType(sel.getType())){
            sel.setType(converter.convertType(sel.getType()));
        }
        if(!converter.isFIRRTLType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isFIRRTLType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Convert result type if necessary
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirMuxOp.getType())){
            resType = converter.convertType(secfirMuxOp.getType());
        }else{
            resType = secfirMuxOp.getType();
        }
        //Replace old secfir operation with new firrtl operation
        rewriter.replaceOpWithNewOp<firrtl::MuxPrimOp>(secfirMuxOp, 
                resType, sel, lhs, rhs);
        return mlir::success();
    }
};

///--Unary Expression Operations-----------------------------------------------

/// Conversation pattern from SecFIR NOT operation to FIRRTL NOT operation.
/// This is a one-to-one replacement conversation.
struct SecFIRNotPrimOpConversion : public mlir::OpConversionPattern<secfir::NotPrimOp> {
    using mlir::OpConversionPattern<secfir::NotPrimOp>::OpConversionPattern;

    /// Translates secfir.NotPrimOp to firrtl.NotPrimOp
    mlir::LogicalResult matchAndRewrite(
            secfir::NotPrimOp secfirNotOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        mlir::Value input = operands[0];
        //Convert input type if not already a FIRRTL type
        if(!converter.isFIRRTLType(input.getType())){
            input.setType(converter.convertType(input.getType()));
        }
        //Convert result type if required
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirNotOp.getType())){
            resType = converter.convertType(secfirNotOp.getType());
        }else{
            resType = secfirNotOp.getType();
        }
        //Replace old SecFIR operation with new FIRRTL operation
        rewriter.replaceOpWithNewOp<firrtl::NotPrimOp>(
                secfirNotOp, 
                resType, 
                operands[0]);
        return mlir::success();
    }
};

///--Constant Expression Operations-----------------------------------------------

/// Conversation pattern from SecFIR constant operation to FIRRTL constant operation.
/// This is a one-to-one replacement conversation.
struct SecFIRConstantOpConversion : public mlir::OpConversionPattern<secfir::ConstantOp> {
    using mlir::OpConversionPattern<secfir::ConstantOp>::OpConversionPattern;

    /// Translates firrtl.ConstantOp to secfir.ConstantOp
    mlir::LogicalResult matchAndRewrite(
            secfir::ConstantOp secfirConstantOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Replace old SecFIR operation with new FIRRTL operation
        rewriter.replaceOpWithNewOp<firrtl::ConstantOp>(
                secfirConstantOp, 
                converter.convertIntType(secfirConstantOp.getType()), 
                secfirConstantOp.value());
        return mlir::success();
    }
};

///--Declaration Operations-----------------------------------------------

/// Conversation pattern from SecFIR node operation to FIRRTL node operation.
/// This is a one-to-one replacement conversation.
struct SecFIRNodeOpConversion : public mlir::OpConversionPattern<secfir::NodeOp> {
    using mlir::OpConversionPattern<secfir::NodeOp>::OpConversionPattern;

    /// Translates secfir.NodeOp to firrtl.NodeOp
    mlir::LogicalResult matchAndRewrite(
            secfir::NodeOp secfirNodeOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        mlir::Value input = operands[0];
        //Convert input type if not already a SecFIR type
        if(!converter.isFIRRTLType(input.getType())){
            input.setType(converter.convertType(input.getType()));
        }
        //Convert result type if necessary
        mlir::Type resType;
        if(!converter.isFIRRTLType(secfirNodeOp.getType())){
            resType = converter.convertType(secfirNodeOp.getType());
        }else{
            resType = secfirNodeOp.getType();
        }
        //Replace old SecFIR operation with new FIRRTL operation
        rewriter.replaceOpWithNewOp<firrtl::NodeOp>(
                secfirNodeOp, 
                resType, 
                input);
        return mlir::success();
    }
};

struct SecFIRRegOpConversion : public mlir::OpConversionPattern<secfir::RegOp> {
    using mlir::OpConversionPattern<secfir::RegOp>::OpConversionPattern;

    mlir::LogicalResult matchAndRewrite(
            secfir::RegOp secfirRegOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
         mlir::Value clock = secfirRegOp.clockVal();
        //Convert input type if not already a secfir type
        if(!converter.isFIRRTLType(clock.getType())){
            clock.setType(converter.convertType(clock.getType()));
        }
        mlir::Value input = operands[0];
        if(!converter.isFIRRTLType(input.getType())){
            input.setType(converter.convertType(input.getType()));
        }
        if(!converter.isFIRRTLType(secfirRegOp.getResult().getType())){
            secfirRegOp.getResult().setType(converter.convertType(secfirRegOp.getResult().getType()));
        }
        //Replace secfir register operation with a firrtl register at
        //the beginning of the module
        rewriter.setInsertionPointToStart(&*(secfirRegOp.getParentRegion()->getBlocks().begin()));
        rewriter.replaceOpWithNewOp<firrtl::RegOp>(
                    secfirRegOp,
                    secfirRegOp.getResult().getType(),
                    clock,
                    secfirRegOp.nameAttr());
        //Add a firrtl connect operation at the end of the block (before doneOp)
        for(mlir::Operation *op=secfirRegOp.getOperation(); !firrtl::isa<firrtl::DoneOp>(op); op = op->getNextNode()){
            rewriter.setInsertionPointAfter(op);
        }
        rewriter.create<firrtl::ConnectOp>(
                    secfirRegOp.getLoc(),
                    secfirRegOp.getResult(), input);
        return mlir::success();
    }
};

///--Statement Operations------------------------------------------------------

/// Conversation pattern from SecFIR connect operation to FIRRTL connect operation.
/// This is a one-to-one replacement conversation.
struct SecFIRConnectOpConversion : public mlir::OpConversionPattern<secfir::ConnectOp> {
    using mlir::OpConversionPattern<secfir::ConnectOp>::OpConversionPattern;

    /// Translates a secfir.ConnectOp to a firrtl.ConnectOp
    mlir::LogicalResult matchAndRewrite(
            secfir::ConnectOp secfirConnectOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        secfir::SecFIRToFIRRTLTypeConverter converter;
        //Get operands
        mlir::Value src = operands[0];
        mlir::Value dest = operands[1];
        //Convert operand type if not already a FIRRTL type
        if(!converter.isFIRRTLType(src.getType())){
            src.setType(converter.convertType(src.getType()));
        }
        if(!converter.isFIRRTLType(dest.getType())){
            dest.setType(converter.convertType(dest.getType()));
        }
        //Replace old SecFIR operation with new FIRRTL operation
        rewriter.replaceOpWithNewOp<firrtl::ConnectOp>(secfirConnectOp, src, dest);
        return mlir::success();
    }
};

///--Conversion Infrastructure-------------------------------------------------

/// Lowering pass from SecFIR to FIRRTL.
/// This pass starts with an CircuitOp
void secfir::SecFIRToFIRRTLConversionPass::runOnOperation() {
    //Define legal and illegal dialects
    mlir::ConversionTarget target(getContext());
    target.addLegalDialect<firrtl::FIRRTLDialect>();
    target.addIllegalDialect<secfir::SecFIRDialect>();

    mlir::OwningRewritePatternList patterns;
    secfir::SecFIRToFIRRTLTypeConverter converter;
    //Populate converstion pattern list
    patterns.insert<SecFIRCircuitOpConversion, 
                    SecFIRFMyModuleOpConversion,
                    SecFIRInstanceOpConversion,
                    SecFIROrPrimOpConversion,
                    SecFIRXorPrimOpConversion,
                    SecFIRMuxPrimOpConversion,
                    SecFIRAndPrimOpConversion, 
                    SecFIRNotPrimOpConversion,
                    SecFIRConstantOpConversion,
                    SecFIRRegOpConversion,
                    SecFIRNodeOpConversion,
                    SecFIRConnectOpConversion>(&getContext());
    mlir::populateFuncOpTypeConversionPattern(patterns, &getContext(), converter);
    //Execute actual converstion
    if (mlir::failed(mlir::applyFullConversion(getOperation(), target, std::move(patterns))))
        signalPassFailure();
}

std::unique_ptr<mlir::Pass> secfir::createSecFIRToFIRRTLConversionPass() {
  return std::make_unique<secfir::SecFIRToFIRRTLConversionPass>();
}

void secfir::registerSecFIRToFIRRTLConversionPass(){
    mlir::PassRegistration<secfir::SecFIRToFIRRTLConversionPass>(
        "secfir-to-firrtl", 
        "Conversion from SecFIR to FIRRTL",
        []() -> std::unique_ptr<mlir::Pass>{return secfir::createSecFIRToFIRRTLConversionPass();});
}