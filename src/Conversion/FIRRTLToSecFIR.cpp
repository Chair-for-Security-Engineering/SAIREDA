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

#include "Conversion/FIRRTLToSecFIR.h"
#include "mlir/Transforms/GreedyPatternRewriteDriver.h"

using namespace circt;

namespace circt{
namespace firrtl{

///--Type Converter------------------------------------------------------------
    struct FIRRTLToSecFIRTypeConverter : public mlir::TypeConverter{
            FIRRTLToSecFIRTypeConverter() {addConversion(convertType);}

        static secfir::SecFIRType convertType(mlir::Type type) {
            mlir::MLIRContext *ctx = type.getContext();
            // Handle clock type
            if (type.isa<firrtl::ClockType>())
                return secfir::ClockType::get(ctx);
            // Handle reset type
            else if(type.isa<firrtl::ResetType>())
                return secfir::ResetType::get(ctx);
            //Handle asynchoneos reset
            else if(type.isa<firrtl::AsyncResetType>())
                return secfir::AsyncResetType::get(ctx);
            // Handle signed integer
            else if(type.isa<firrtl::SIntType>()){
                auto width = type.dyn_cast<firrtl::SIntType>().getBitWidthOrSentinel();
                return secfir::SIntType::get(ctx, width);
            // Handle unsigned integer
            } else if(type.isa<firrtl::UIntType>()){
                auto width = type.dyn_cast<firrtl::UIntType>().getBitWidthOrSentinel();;
                return secfir::UIntType::get(ctx, width);
            //Handle analog type
            } else if(type.isa<firrtl::AnalogType>()){
                auto width = type.dyn_cast<firrtl::AnalogType>().getBitWidthOrSentinel();
                return secfir::AnalogType::get(ctx, width);
            //Handle all flip types
            } else if(type.isa<firrtl::FlipType>()){
                auto flipType = type.dyn_cast<firrtl::FlipType>();
                //Flipped signed integer
                if(flipType.getElementType().isa<firrtl::SIntType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            firrtl::SIntType>().getBitWidthOrSentinel();
                    auto internType = secfir::SIntType::get(ctx, width);
                    return secfir::FlipType::get(internType);
                    // return secfir::SIntType::get(ctx, width);
                //Flipped unsigned integer
                } else if(flipType.getElementType().isa<firrtl::UIntType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            firrtl::UIntType>().getBitWidthOrSentinel();
                    auto internType = secfir::UIntType::get(ctx, width);
                    return secfir::FlipType::get(internType);
                    // return secfir::UIntType::get(ctx, width);
                //Flipped analog type
                } else if (flipType.getElementType().isa<firrtl::AnalogType>()){
                    auto width = flipType.getElementType().dyn_cast<
                            firrtl::AnalogType>().getBitWidthOrSentinel();
                    auto internType = secfir::AnalogType::get(ctx, width);
                    return secfir::FlipType::get(internType);
                    // return secfir::AnalogType::get(ctx, width);
                }
            }
            return nullptr;
        }

        ///Converter from FIRRTL IntType to SecFIR IntType
        ///(Required for conversation of ConstantOp)
        static secfir::IntType convertIntType(mlir::Type type){
            mlir::MLIRContext *ctx = type.getContext();
            if(type.isa<firrtl::SIntType>()){
                auto width = type.dyn_cast<firrtl::SIntType>().getBitWidthOrSentinel();
                return secfir::SIntType::get(ctx, width);
            // Handle unsigned integer
            } else if(type.isa<firrtl::UIntType>()){
                auto width = type.dyn_cast<firrtl::UIntType>().getBitWidthOrSentinel();
                return secfir::UIntType::get(ctx, width);
            }
        }

        static bool isSecFIRType(mlir::Type type){
            bool returnValue = false;
            if(type.isa<secfir::SecFIRType>()){
                returnValue = true;
            }
            return returnValue;
        }

    };
}
}

///--Structural Operations-----------------------------------------------------

/// Conversation pattern from FIRRTL circuits to SecFIR circuits.
/// This is a one-to-one replacement conversation.
struct FIRRTLCircuitOpConversion : public mlir::OpConversionPattern<firrtl::CircuitOp> {
    using mlir::OpConversionPattern<firrtl::CircuitOp>::OpConversionPattern;

    ///Translates a firrtl.CircuitOp to a secfir.CircuitOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::CircuitOp firrtlCircuitOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        //Create a SecFIR circuit operation with the same name as the FIRRTL circuit operation    
        secfir::CircuitOp secfirCircuitOp = rewriter.create<secfir::CircuitOp>(
                firrtlCircuitOp.getLoc(), rewriter.getStringAttr(firrtlCircuitOp.name()));
        
        //Insert content of firrtl.CircuitOp into the new secfir.CircuitOp
        rewriter.mergeBlockBefore(firrtlCircuitOp.getBody(), 
                    &secfirCircuitOp.getBody()->getOperations().front());
        //Clone block back to old operation to prevent circuit form being empty
        //mlir::BlockAndValueMapping mapper;
        //secfirCircuitOp.body().cloneInto(&firrtlCircuitOp.getRegion(), mapper);
        //Remove firrtl.doneOp of the old firrtl.CircuitOp
        bool removed = false;
        for(mlir::Operation &op : secfirCircuitOp.getBody()->getOperations()){
            if(firrtl::dyn_cast<firrtl::DoneOp>(op)){
                rewriter.eraseOp(&op);
                removed = true;
            }
        }
        assert(removed && "No corresponding firrtl.DoneOp for the circuit found!");

        //Delete old firrtl.CircuitOp
        rewriter.eraseOp(firrtlCircuitOp);     
        return mlir::success();
  }

};

/// Conversation pattern from FIRRTL modules to SecFIR modules.
/// This is a one-to-one replacement conversation.
struct FIRRTLFModuleOpConversion : public mlir::OpConversionPattern<firrtl::FModuleOp> {
    using mlir::OpConversionPattern<firrtl::FModuleOp>::OpConversionPattern;

    ///Translates firrtl.FModuleOp to secfir.ModuleOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::FModuleOp firrtlModule, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        //Create a type converter from FIRRTL to SecFIR types
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Convert types of input/output ports of the FIRRTL module
        llvm::SmallVector<secfir::ModulePortInfo, 4> secfirPorts;
        secfir::SmallVector<firrtl::ModulePortInfo, 4> firrtlPorts;
        //Retrive port informations form the original FIRRTL module
        firrtlModule.getPortInfo(firrtlPorts);
        //Do the actual conversion for all ports
        for(firrtl::ModulePortInfo firrtlPort : firrtlPorts){ 
            secfir::SecFIRType secfirPortType = converter.convertType(firrtlPort.type);
            secfirPorts.push_back({firrtlPort.name, secfirPortType});
        }
        //Create a new SecFIR module with the new port types
        mlir::ArrayRef<secfir::ModulePortInfo> portArray(secfirPorts);
        rewriter.setInsertionPointAfter(firrtlModule);
        secfir::ModuleOp secfirModule = rewriter.create<secfir::ModuleOp>(
                firrtlModule.getLoc(), rewriter.getStringAttr(firrtlModule.getName()), 
                portArray);
        //Get a mapping from old input values to new input values
        mlir::BlockAndValueMapping blockValueMapping;
        for(size_t i=0; i<secfirModule.getArguments().size(); i++){
            blockValueMapping.map(firrtlModule.getArguments()[i], 
                            secfirModule.getArguments()[i]);
        }
        //Clone all operations from the old module to the new module (except for DoneOp)
        rewriter.setInsertionPointToStart(&secfirModule.getBody().getBlocks().front());
        for(auto &op : firrtlModule.getBodyBlock()->getOperations()){
            if(!secfir::isa<firrtl::DoneOp>(op)){
                mlir::Operation *newOp = rewriter.clone(op, blockValueMapping);
            }
        }
        //Identify all output values in the new module
        llvm::SmallVector<mlir::Value, 1> outputPorts;
        mlir::DenseMap<mlir::Value, mlir::Value> ouputValueMap;
        llvm::SmallVector<mlir::Operation*, 1> toDelete;
        mlir::Operation *outputOp;
        //Get all old ouput values
        for(auto port : firrtlModule.getArguments()){
            if(port.getType().isa<firrtl::FlipType>())
                outputPorts.push_back(port);
        }
        //Find ConnectOps connecting values to the outputs
        for(mlir::Operation &op : secfirModule.getBody().getBlocks().front().getOperations()){
            if(auto connectOp = firrtl::dyn_cast<firrtl::ConnectOp>(op)){
                for(mlir::Value port : outputPorts){
                    if(connectOp.dest() == port){
                        ouputValueMap[port] = connectOp.src();
                        toDelete.push_back(&op);
                    }
                }
            }
            //Identify the output operation of the new module
            if(secfir::isa<secfir::OutputOp>(op)){
                outputOp = &op;
            }
        }
        //Replace the current output operation with a new output operation 
        //that has the proper output values
        mlir::SmallVector<mlir::Value, 1> outputValues;
        for(auto port : outputPorts){
            outputValues.push_back(ouputValueMap[port]);
            port.replaceAllUsesWith(secfirModule.getArgument(0));
        }
        rewriter.setInsertionPointAfter(outputOp);
        rewriter.create<secfir::OutputOp>(outputOp->getLoc(), outputValues);
        rewriter.eraseOp(outputOp);
        //Remove all connection operation that are not necessary any more
        for(auto connect : toDelete){
            rewriter.eraseOp(connect);
        }
        //Erase old firrtl.ModuleOp
        rewriter.eraseOp(firrtlModule);
        return mlir::success();
    }

};

///--Binary Expression Operations----------------------------------------------

/// Conversation pattern from FIRRTL AND operation to SecFIR AND operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLAndPrimOpConversion : public mlir::OpConversionPattern<firrtl::AndPrimOp> {
    using mlir::OpConversionPattern<firrtl::AndPrimOp>::OpConversionPattern;

    /// Translates firrtl.AndPrimOp to secfir.AndPrimOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::AndPrimOp firrtlAndOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a secfir type
        if(!converter.isSecFIRType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isSecFIRType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::AndPrimOp>(firrtlAndOp, 
                converter.convertType(firrtlAndOp.getType()), lhs, rhs);
        return mlir::success();
    }
};
/// Conversation pattern from FIRRTL OR operation to SecFIR OR operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLOrPrimOpConversion : public mlir::OpConversionPattern<firrtl::OrPrimOp> {
    using mlir::OpConversionPattern<firrtl::OrPrimOp>::OpConversionPattern;

    /// Translates firrtl.OrPrimOp to secfir.OrPrimOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::OrPrimOp firrtlOrOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a secfir type
        if(!converter.isSecFIRType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isSecFIRType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::OrPrimOp>(firrtlOrOp, 
                converter.convertType(firrtlOrOp.getType()), lhs, rhs);
        return mlir::success();
    }
};
/// Conversation pattern from FIRRTL XOR operation to SecFIR XOR operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLXorPrimOpConversion : public mlir::OpConversionPattern<firrtl::XorPrimOp> {
    using mlir::OpConversionPattern<firrtl::XorPrimOp>::OpConversionPattern;

    /// Translates firrtl.XorPrimOp to secfir.XorPrimOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::XorPrimOp firrtlXorOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Get operands
        mlir::Value lhs = operands[0];
        mlir::Value rhs = operands[1];
        //Convert operand types if not already a secfir type
        if(!converter.isSecFIRType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isSecFIRType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //lhs.setType(converter.convertType(lhs.getType()));
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::XorPrimOp>(firrtlXorOp, 
                converter.convertType(firrtlXorOp.getType()), lhs, rhs);
        return mlir::success();
    }
};

/// Conversation pattern from FIRRTL MUX operation to SecFIR MUX operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLMuxPrimOpConversion : public mlir::OpConversionPattern<firrtl::MuxPrimOp> {
    using mlir::OpConversionPattern<firrtl::MuxPrimOp>::OpConversionPattern;

    /// Translates firrtl.MuxPrimOp to secfir.MuxPrimOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::MuxPrimOp firrtlMuxOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Get operands
        mlir::Value sel = operands[0];
        mlir::Value lhs = operands[1];
        mlir::Value rhs = operands[2];

        //Convert operand types if not already a secfir type
        if(!converter.isSecFIRType(sel.getType())){
            sel.setType(converter.convertType(sel.getType()));
        }
        if(!converter.isSecFIRType(lhs.getType())){
            lhs.setType(converter.convertType(lhs.getType()));
        }
        if(!converter.isSecFIRType(rhs.getType())){
            rhs.setType(converter.convertType(rhs.getType()));
        }
        //lhs.setType(converter.convertType(lhs.getType()));
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::MuxPrimOp>(firrtlMuxOp, 
                converter.convertType(firrtlMuxOp.getType()), sel, lhs, rhs);
        return mlir::success();
    }
};


///--Unary Expression Operations-----------------------------------------------

/// Conversation pattern from FIRRTL NOT operation to SecFIR NOT operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLNotPrimOpConversion : public mlir::OpConversionPattern<firrtl::NotPrimOp> {
    using mlir::OpConversionPattern<firrtl::NotPrimOp>::OpConversionPattern;

    /// Translates firrtl.NotPrimOp to secfir.NotPrimOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::NotPrimOp firrtlNotOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        mlir::Value input = operands[0];
        //Convert input type if not already a secfir type
        if(!converter.isSecFIRType(input.getType())){
            input.setType(converter.convertType(input.getType()));
        }
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::NotPrimOp>(firrtlNotOp, 
                converter.convertType(firrtlNotOp.getType()), operands[0]);
        return mlir::success();
    }
};

///--Constant Expression Operations-----------------------------------------------

/// Conversation pattern from FIRRTL constant operation to SecFIR constant operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLConstantOpConversion : public mlir::OpConversionPattern<firrtl::ConstantOp> {
    using mlir::OpConversionPattern<firrtl::ConstantOp>::OpConversionPattern;

    /// Translates firrtl.ConstantOp to secfir.ConstantOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::ConstantOp firrtlConstantOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::ConstantOp>(
                firrtlConstantOp, 
                converter.convertIntType(firrtlConstantOp.getType()), 
                firrtlConstantOp.value());
        return mlir::success();
    }
};

///--Declaration Operations-----------------------------------------------

/// Conversation pattern from FIRRTL node operation to SecFIR node operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLNodeOpConversion : public mlir::OpConversionPattern<firrtl::NodeOp> {
    using mlir::OpConversionPattern<firrtl::NodeOp>::OpConversionPattern;

    /// Translates firrtl.NodeOp to secfir.NodeOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::NodeOp firrtlNodeOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {   
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        mlir::Value input = operands[0];
        //Convert input type if not already a secfir type
        if(!converter.isSecFIRType(input.getType())){
            input.setType(converter.convertType(input.getType()));
        }
        //Convert output type if not already secfir type
        mlir::Type destType = firrtlNodeOp.getType();
        if(!converter.isSecFIRType(firrtlNodeOp.getType())){
            destType = converter.convertIntType(firrtlNodeOp.getType());
        }
        //Replace old firrtl operation with new secfir operation
        rewriter.replaceOpWithNewOp<secfir::NodeOp>(
                firrtlNodeOp, 
                destType, 
                input);
        return mlir::success();
    }
};

/// Conversation pattern from FIRRTL register operation to SecFIR register operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLRegOpConversion : public mlir::OpConversionPattern<firrtl::RegOp> {
    using mlir::OpConversionPattern<firrtl::RegOp>::OpConversionPattern;

    /// Translates firrtl.NodeOp to secfir.NodeOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::RegOp firrtlRegOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
         mlir::Value clock = firrtlRegOp.clockVal();
        //Convert input type if not already a secfir type
        if(!converter.isSecFIRType(clock.getType())){
            clock.setType(converter.convertType(clock.getType()));
        }
        //Find the corresponding firrtl connection operation
        mlir::Operation *mlirOp = firrtlRegOp.getOperation();
        for(auto user: mlirOp->getUsers()){
            if(firrtl::isa<firrtl::ConnectOp>(user)){
                firrtl::ConnectOp conOp = firrtl::dyn_cast<firrtl::ConnectOp>(user);
                if(conOp.dest() == firrtlRegOp.getResult()){
                    //Replace firrtl register with a secfir register
                    //at the place of the firrtl connection operation
                    rewriter.setInsertionPointAfter(conOp);
                    rewriter.replaceOpWithNewOp<secfir::RegOp>(
                            firrtlRegOp,
                            converter.convertType(firrtlRegOp.getType()),
                            conOp.src(),
                            clock,
                            firrtlRegOp.nameAttr());
                    break;
                }
            }
        }
        return mlir::success();
    }
};

/// Conversation pattern for FIRRTL wire operations, which are replaced 
/// by the source of the corresponding FIRRTL connect operation.
struct FIRRTLWireOpConversion : public mlir::OpConversionPattern<firrtl::WireOp>{
    using mlir::OpConversionPattern<firrtl::WireOp>::OpConversionPattern;

    /// Replace firrtl.wire with the source of the correspinding
    /// firrtl.wire operation
    mlir::LogicalResult matchAndRewrite(
        firrtl::WireOp firrtlWireOp,
        mlir::ArrayRef<mlir::Value> operands,
        mlir::ConversionPatternRewriter &rewriter
    ) const final {
        //Get an mlir operation instance to get all users of the wire
        mlir::Operation *mlirOp = firrtlWireOp.getOperation();
        //Find the firrtl.connect operation that belongs to the wire
        for(auto user: mlirOp->getUsers()){
            if(firrtl::isa<firrtl::ConnectOp>(user)){
                firrtl::ConnectOp conOp = firrtl::dyn_cast<firrtl::ConnectOp>(user);
                if(conOp.dest() == firrtlWireOp.getResult()){
                    //Replace the wire with the source of the connect operations
                    rewriter.replaceOp(firrtlWireOp, conOp.src());
                    break;
                }
            }
         }
        return mlir::success();
    }
};

///--Statement Operations------------------------------------------------------

/// Conversation pattern from FIRRTL connect operation to SecFIR connect operation.
/// This is a one-to-one replacement conversation.
struct FIRRTLConnectOpConversion : public mlir::OpConversionPattern<firrtl::ConnectOp> {
    using mlir::OpConversionPattern<firrtl::ConnectOp>::OpConversionPattern;

    /// Translates a firrtl.ConnectOp to a secfir.ConnectOp
    mlir::LogicalResult matchAndRewrite(
            firrtl::ConnectOp firrtlConnectOp, 
            mlir::ArrayRef<mlir::Value> operands, 
            mlir::ConversionPatternRewriter &rewriter
    ) const final {
        firrtl::FIRRTLToSecFIRTypeConverter converter;
        //Get operands
        mlir::Value src = operands[1];
        mlir::Value dest = operands[0];
        //Convert operand type if not already a secfir type
        if(!converter.isSecFIRType(src.getType())){
            src.setType(converter.convertType(src.getType()));
        }
        if(!converter.isSecFIRType(dest.getType())){
            dest.setType(converter.convertType(dest.getType()));
        }
        if(dest.getDefiningOp() != nullptr){
            //Remove connect operation if it has a register as destination
            if(secfir::isa<secfir::RegOp>(dest.getDefiningOp())){
                rewriter.eraseOp(firrtlConnectOp);
            //Remove connect operation if it has a node as destination
            //can happen because of the removal of wire operations
            } else if(secfir::isa<secfir::NodeOp>(dest.getDefiningOp())){  
                rewriter.eraseOp(firrtlConnectOp);
            } else if(firrtl::isa<firrtl::NodeOp>(dest.getDefiningOp())){
                rewriter.eraseOp(firrtlConnectOp);
            //Remove connect operation if the destination is a firrtl wire
            //(should be already handled by conversation of wire operation)
            } else if(secfir::isa<firrtl::WireOp>(dest.getDefiningOp())){
                rewriter.eraseOp(firrtlConnectOp);
            }
        //Remove useless connect operations that connect a value to itself,
        //can happen because of the removal of wire operations
        }else if(dest == src){
            rewriter.eraseOp(firrtlConnectOp);
        }else{
            //Otherwise replace old firrtl operation with new secfir operation
            rewriter.replaceOpWithNewOp<secfir::ConnectOp>(firrtlConnectOp, dest, src);
        }
        return mlir::success();
    }
};

///--Conversion Infrastructure-------------------------------------------------

/// Lowering pass from Low SecFIR to Netlist SecFIR.
/// This pass starts with an CircuitOp
void firrtl::FIRRTLToSecFIRConversionPass::runOnOperation() {
    //Define legal and illegal dialects
    mlir::ConversionTarget target(getContext());
    target.addLegalDialect<secfir::SecFIRDialect>();
    target.addIllegalDialect<firrtl::FIRRTLDialect>();

    mlir::OwningRewritePatternList patterns;
    firrtl::FIRRTLToSecFIRTypeConverter converter;
    //Populate converstion pattern list
    patterns.insert<FIRRTLCircuitOpConversion, 
                    FIRRTLFModuleOpConversion,
                    FIRRTLOrPrimOpConversion,
                    FIRRTLXorPrimOpConversion,
                    FIRRTLMuxPrimOpConversion,
                    FIRRTLAndPrimOpConversion, 
                    FIRRTLNotPrimOpConversion,
                    FIRRTLConstantOpConversion,
                    FIRRTLRegOpConversion,
                    FIRRTLWireOpConversion,
                    FIRRTLNodeOpConversion,
                    FIRRTLConnectOpConversion>(&getContext());
    mlir::populateFuncOpTypeConversionPattern(patterns, &getContext(), converter);
    //Execute actual converstion
    // if (mlir::failed(mlir::applyFullConversion(getOperation(), target, std::move(patterns))))
    //     signalPassFailure();
    mlir::applyFullConversion(getOperation(), target, std::move(patterns));
}

std::unique_ptr<mlir::Pass> firrtl::createFIRRTLToSecFIRConversionPass() {
  return std::make_unique<firrtl::FIRRTLToSecFIRConversionPass>();
}

void firrtl::registerFIRRTLToSecFIRConversionPass(){
    mlir::PassRegistration<firrtl::FIRRTLToSecFIRConversionPass>(
        "firrtl-to-secfir", 
        "Conversion from FIRRTL to SecFIR",
        []() -> std::unique_ptr<mlir::Pass>{return firrtl::createFIRRTLToSecFIRConversionPass();});
}