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
//Includes from LLVM and MLIR
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/InitLLVM.h"
#include "mlir/Support/FileUtilities.h"
#include "mlir/Pass/PassManager.h"
#include "mlir/Transforms/Passes.h"
//Includes from CIRCT
#include "circt/Dialect/RTL/Dialect.h"
#include "circt/FIRParser.h"
#include "circt/EmitVerilog.h"
//Includes from SecFIR project
#include "SecFIR/SecFIRDialect.h"
#include "SecFIR/Ops.h"
#include "Passes/Passes.h"
#include "Passes/IRTransformation.h"
#include "Passes/GadgetInsertion.h"
#include "Passes/TransformationPasses.h"
#include "Passes/OptimizationPasses.h"
#include "Passes/OptimizeLatency.h"
#include "Conversion/FIRRTLToSecFIR.h"
#include "Conversion/SecFIRToFIRRTL.h"

namespace cl = llvm::cl;
using namespace mlir;
using namespace circt;

/// -------------------------------------------------------
/// --- Command Line Options ---
/// -------------------------------------------------------
static cl::opt<std::string> inputFilename("i",
	cl::desc("<input fir file>"),
	cl::init("-"),
	cl::value_desc("filename"));

static cl::opt<std::string> outputFilename("o", 
	cl::desc("<output verilog file>"), 
	cl::init("-"),
	cl::value_desc("filename"));

static cl::opt<bool> ignoreFIRLocations("ignore-fir-locators",
	cl::desc("ignore the @info locations in the .fir file"),
	cl::init(false));

static cl::opt<bool> passTiming("pass-timings",
	cl::desc("print timing behavior of the passes"),
	cl::init(false));

/// -------------------------------------------------------
/// --- Main Function ---
/// -------------------------------------------------------
int main(int argc, char** argv)
{
	//Register passes
	llvm::InitLLVM y(argc, argv);
	secfir::registerDistributeRandomnessPass();
	firrtl::registerFIRRTLToSecFIRConversionPass();
	secfir::registerSecFIRToFIRRTLConversionPass();
	secfir::registerInsertGadgetsPass();
	secfir::registerDefineGadgetTypePass();
	secfir::registerOptimizeAsynchonGadgetLatencyPass();
	secfir::registerToXAGPass();
	secfir::registerPipeliningPass();
	secfir::registerMuxToDLogicPass();
	secfir::registerFlattenCombinationalNetworkHierarchyPass();
	secfir::registerInsertCombinationalNetworkHierarchyPass();
	secfir::registerInsertGateModulePass();
	secfir::registerReplaceRedundantOperationsPass();
	secfir::registerRemoveDoubleNotOpPass();
	secfir::registerRemoveNodeOpPass();
	secfir::registerSetShareAttributePass();
	secfir::registerInsertGadgetsLogicPass();
	secfir::registerMuxToDLogicPass();
	secfir::registerMajorityToLogicPass();
  	mlir::registerPassManagerCLOptions();
	//Create a pass pipeline
	mlir::PassPipelineCLParser passPipeline("", "Compiler passes to run");
	//Read command line arguments
	cl::ParseCommandLineOptions(argc, argv, "A simple test for SecFIR\n");
	// Set up the input file.
	std::string errorMessage;
	auto input = openInputFile(inputFilename, &errorMessage);
	if (!input) {
		llvm::errs() << errorMessage << "\n";
		return 1;
	}
	//--Parse FIRRTL file --------------------------------------------------------
	//Set up MLIR Context
	MLIRContext context;
	// Register FIRRTL Dialect
	context.loadDialect<firrtl::FIRRTLDialect>();
	// Register SecFIR Dialect
	context.loadDialect<secfir::SecFIRDialect>();
	//Prepare source file
	llvm::SourceMgr sourceMgr;
	sourceMgr.AddNewSourceBuffer(std::move(input), llvm::SMLoc());
	SourceMgrDiagnosticHandler sourceMgrHandler(sourceMgr, &context);
	// Nothing in the parser is threaded.  Disable synchronization overhead.
	context.disableMultithreading();
	//Translation pass from FIRRTL to SecFIR
	PassManager conversionPassManager(&context);
	OpPassManager& conversionPassManagerCircuit = 
				conversionPassManager.nest<firrtl::CircuitOp>();
	conversionPassManagerCircuit.addPass(
				circt::firrtl::createFIRRTLToSecFIRConversionPass());
	PassManager backConversionPassManager(&context);
	OpPassManager& backConversionPassManagerCircuit = 
				backConversionPassManager.nest<secfir::CircuitOp>();
	backConversionPassManagerCircuit.addPass(
				circt::secfir::createSecFIRToFIRRTLConversionPass());
	//Actual parsing of input
	FIRParserOptions options;
	options.ignoreInfoLocators = ignoreFIRLocations;
	OwningModuleRef module = parseFIRFile(sourceMgr, &context, options);
	if (!module)
		return 1;
	// Allow optimizations to run multithreaded.
	context.disableMultithreading(false);
	//--Run Parse Manager -----------------------------------------------------
	// Apply any pass manager command line options.
  	PassManager pm(&context, OpPassManager::Nesting::Implicit);
  	applyPassManagerCLOptions(pm);
	// Build the provided pipeline.
	if (failed(passPipeline.addToPipeline(pm)))
		return 1;
	//Convert design from FIRRTL to SecFIR
	conversionPassManager.run(*module);
	// Run the pipeline.
	if(passTiming) pm.enableTiming();
	pm.run(*module);
	//--Output Verilog File----------------------------------------------------
	if(outputFilename != "-"){
		//Convert back from SecFIR to FIRRTL
		backConversionPassManager.run(*module);
		// Open output file
		std::error_code OutErrorInfo;
		llvm::raw_fd_ostream outFile(
			llvm::StringRef(outputFilename), OutErrorInfo, llvm::sys::fs::F_None);
		// Translate module to Verilog
		emitVerilog(*module, outFile);
	}
	return 0;
}
