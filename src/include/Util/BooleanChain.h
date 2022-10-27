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

#ifndef BOOLEANCHAIN_H
#define BOOLEANCHAIN_H

#include<string>

namespace secutil{
	enum BooleanOperation {
		const_0 = 0x0,
		AND = 0x1,
    	a_and_not_b = 0x2,
		a = 0x3,
		not_a_and_b = 0x4,
		b = 0x5,
		XOR = 0x6,
		OR = 0x7,
		NOR = 0x8,
		XNOR = 0x9,
		not_b = 0xA,
		not__not_a_and_b = 0xB,
		not_a = 0xC,
		not__a_and_not_b = 0xD,
		NAND = 0xE,
		const_1 = 0xF
	};

	class BooleanChainElement{
	    int operation = -1;
		int outputFunction = -1;
		unsigned input_a;
		unsigned input_b;
		unsigned nodeId;
		int shareDomainId = -1;
	public:
		BooleanChainElement(){};

		BooleanChainElement(unsigned id, int op, unsigned a, unsigned b, int out){
			nodeId = id;
			operation = op;
			input_a = a;
			input_b = b;
			outputFunction = out;
		}

		BooleanChainElement(unsigned id, int op, unsigned a, unsigned b, int out, int domain){
			nodeId = id;
			operation = op;
			input_a = a;
			input_b = b;
			outputFunction = out;
			shareDomainId = domain;
		}

		unsigned getId(){
			return nodeId;
		}
		int getOperation(){
			return operation;
		}
		std::string getOperationAsString(){
			switch (operation)
			{
			case const_0: return "const_0";
			case AND: return "AND";
			case a_and_not_b: return "a_and_not(b)";
			case a: return "a";
			case not_a_and_b: return "not(a)_and_b";
			case b: return "b";
			case XOR: return "XOR";
			case OR: return "OR";
			case NOR: return "NOR";
			case XNOR: return "XNOR";
			case not_b: return "not_b";
			case not__not_a_and_b: return "not(not(a)_and_b)";
			case not_a: return "not_a";
			case not__a_and_not_b: return "not(a_and_not(b))";
			case NAND: return "NAND";
			case const_1: return "const_1";
			default: return "UNKNOWN OPERATION";
			}
		}
		unsigned getInputA(){
			return input_a;
		}
		unsigned getInputB(){
			return input_b;
		}
		int getOutputFunction(){
			return outputFunction;
		}
		int getShareDomain(){
			return shareDomainId;
		}
		std::string to_string(){
			std::string str = "Operation " + std::to_string(nodeId) + 
					": " + this->getOperationAsString() + "(" + 
					std::to_string(input_a) + "," + 
					std::to_string(input_b) + ")";
            if(outputFunction != -1){
                str = str + " output of f_" + std::to_string(outputFunction);
            }
            return str;
    	}
	};
}
#endif // !BOOLEANCHAIN_H