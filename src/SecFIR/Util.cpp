// #include "SecFIR/SecFIRDialect.h"
// #include "Passes/Passes.h"

// #include "tinyxml.h"

// using namespace circt::secfir;


// Function that parses a given XML file that specifies the security level of 
// input signals of modules in the following form:
//
// <Module name=moduleName>
//		<Signal>signalName_1</Signal>
//		<Signal>signalName_2</Signal>
// </Module>
//
// Multiple module might be specified in the same XML file.
// Currently a security level is not supported!
// void circt::secfir::parseXmlFile(const char* filename, std::list<ModuleSecureSignals> moduleList) {
// 	//std::list<secfir::ModuleSecureSignals> moduleList;
// 	//--Parse XML file------------------------------------------------------------
// 	TiXmlDocument doc(filename);
// 	bool loadOkay = doc.LoadFile();
// 	if (loadOkay) {
// 		//Parse all child nodes of the document (Decleration is ignored)
// 		TiXmlNode* moduleNode;
// 		for (moduleNode = doc.FirstChild(); moduleNode != 0; moduleNode = moduleNode->NextSibling()) {
// 			const char* moduleName = nullptr;
// 			//Parse a module
// 			if (moduleNode->Type() == TiXmlNode::TINYXML_ELEMENT) {
// 				//Verify that it is a module
// 				if (strcmp(moduleNode->Value(), "Module") == 0) {
// 					//Set module name
// 					moduleName = moduleNode->ToElement()->FirstAttribute()->Value();
// 				}
// 				else {
// 					llvm::errs() << "Parsing Error: Module required!" << "\n";
// 					return;
// 				}
// 				//For each module parse all signals
// 				TiXmlNode* signalNode;
// 				std::list<const char*> signalList;
// 				for (signalNode = moduleNode->FirstChild(); signalNode != 0; signalNode = signalNode->NextSibling()) {
// 					//Verify that it is a signal
// 					if (signalNode->Type() == TiXmlNode::TINYXML_ELEMENT) {
// 						if (strcmp(signalNode->Value(), "Signal") == 0) {
// 							const char* signalName = signalNode->FirstChild()->ToText()->Value();
// 							//Add signal name to list
// 							signalList.push_back(signalName);
// 						}
// 						else {
// 							llvm::errs() << "Parsing Error: Signal required!" << "\n";
// 							return;
// 						}
// 					}
// 				}
// 				//Create a ModuleSecureSignals object and add it to the list
// 				std::list<int> emptyList;
// 				moduleList.push_back(ModuleSecureSignals(moduleName, signalList, emptyList));
// 			}
// 		}
// 	}
// 	return;
// }