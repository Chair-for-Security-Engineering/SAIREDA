# -----------------------------------------------------------------
# COMPANY : Ruhr-University Bochum, Chair for Security Engineering
# AUTHOR  : Jakob Feldtkeller (jakob.feldtkeller@rub.de)
# -----------------------------------------------------------------
#
# Copyright (c) 2022, Jakob Feldtkeller
#
# All rights reserved.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Please see license.rtf and README for license and further instructions.

cmake_minimum_required (VERSION 3.8)
set(CMAKE_CXX_STANDARD 14 CACHE STRING "C++ standard to conform to")

project ("secfir_eda")

include(CTest)
enable_testing()

# Set Path to CIRCT root directory and directory with Z3 library
# CHANGE HERE!!!
set(CIRCT_PATH "[CIRCT_ROOT]")
set(Z3_PATH "[Z3_DIRECTORY]")

#Find LLVM 
find_package(LLVM 12.0.0 REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
#Include LLVM
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

#Find MLIR
find_package(MLIR REQUIRED CONFIG)
message(STATUS "Found MLIR ${MLIR_PACKAGE_VERSION}")
message(STATUS "Using MLIRConfig.cmake in: ${MLIR_DIR}")
#Include MLIR
include_directories(${MLIR_INCLUDE_DIRS})
add_definitions(${MLIR_DEFINITIONS})

#Include Circt
include_directories(${CIRCT_PATH}/include)
include_directories(${CIRCT_PATH}/build/include)


#include tools
list(APPEND CMAKE_MODULE_PATH "${MLIR_CMAKE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(TableGen)
include(AddLLVM)
include(AddMLIR)
include(HandleLLVMOptions)

#Include system libraries
include_directories(/usr/include)

#Include directories from project
add_subdirectory(src/)
include_directories(src/include)


#Generate tbgen for SecFIR in subdirectory
set(LLVM_TARGET_DEFINITIONS src/include/SecFIR/SecFIR.td)
mlir_tablegen(SecFIR.h.inc -gen-op-decls)
mlir_tablegen(SecFIR.cpp.inc -gen-op-defs)
mlir_tablegen(SecFIRTypes.h.inc -gen-typedef-decls)
mlir_tablegen(SecFIRTypes.cpp.inc -gen-typedef-defs)
mlir_tablegen(SecFIRDialect.h.inc -gen-dialect-decls -dialect=secfir)
mlir_tablegen(SecFIREnums.h.inc -gen-enum-decls)
mlir_tablegen(SecFIREnums.cpp.inc -gen-enum-defs)
add_public_tablegen_target(MLIRSecFIRIncGen)  



#Include target directory for tbgen files
include_directories(build/)

#Set compiler flags
add_compile_options(-fno-rtti)

#Define source code and executable that should be created
add_executable (secfir_eda
    "main.cpp" 
    "src/SecFIR/SecFIRDialect.cpp" 
    "src/SecFIR/Types.cpp" 
    "src/SecFIR/Ops.cpp" 
    "src/SecFIR/OpsFolds.cpp" 
    "src/Conversion/FIRRTLToSecFIR.cpp" 
    "src/Conversion/SecFIRToFIRRTL.cpp" 
    "src/SecFIR/LowerToNetFIR.cpp" 
    "src/Transforms/IRTransformations.cpp"
    "src/Transforms/Optimization.cpp"
    "src/Transforms/XAG.cpp"
    "src/Transforms/OptimizeRandomness/Pass.cpp"
    "src/Transforms/OptimizeRandomness/DistributeRandomness.cpp"
    "src/Transforms/OptimizeRandomness/GadgetDependencies.cpp"
    "src/Transforms/GadgetInsertion/Pass.cpp"
    "src/Transforms/GadgetInsertion/TightProver.cpp"
    "src/Transforms/GadgetInsertion/StrongNonInterference.cpp"
    "src/Transforms/GadgetInsertion/ProbeIsolatingNonInterference.cpp"
    "src/Util/util"
    )

# Find the libraries that correspond to the LLVM components
# that we wish to use
llvm_map_components_to_libnames(llvm_libs support core irreader)
# Link against LLVM libraries
target_link_libraries(secfir_eda ${llvm_libs})
# Link against Circt libraries
target_link_libraries(secfir_eda
    ${CIRCT_PATH}/build/lib/libMLIRFIRRTL.a
    ${CIRCT_PATH}/build/lib/libCIRCTFIRParser.a
    ${CIRCT_PATH}/build/lib/libCIRCTEmitVerilog.a
    ${CIRCT_PATH}/build/lib/libMLIRRTL.a
    ${CIRCT_PATH}/build/lib/libMLIRSV.a)

# Link against MLIR libraries
target_link_libraries(secfir_eda
    MLIRSupport
    MLIRStandard  
    MLIRAnalysis 
    MLIRIR 
    MLIRParser 
    MLIRPass 
    MLIRSideEffectInterfaces 
    MLIRTransforms 
    MLIRTranslation)

#Link xml parse library
target_link_libraries(secfir_eda ${Z3_PATH}/libz3.so)

#Set dependency to result from tablegen
add_dependencies(secfir_eda MLIRSecFIRIncGen)
