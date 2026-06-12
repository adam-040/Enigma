ghidra-source code
├── GPL/
│   ├── DMG/
│   │   ├── data/
│   │   │   └── lib/
│   │   │       ├── csframework.jar
│   │   │       ├── hfsx.jar
│   │   │       ├── hfsx_dmglib.jar
│   │   │       └── iharder-base64.jar
│   │   ├── src/
│   │   │   └── dmg/
│   │   │       └── java/
│   │   │           └── mobiledevices/
│   │   └── build.gradle
│   ├── DemanglerGnu/
│   │   ├── src/
│   │   │   ├── demangler_gnu_v2_24/
│   │   │   │   ├── c/
│   │   │   │   │   ├── alloca.c
│   │   │   │   │   ├── argv.c
│   │   │   │   │   ├── cp-demangle.c
│   │   │   │   │   ├── cplus-dem.c
│   │   │   │   │   ├── dyn-string.c
│   │   │   │   │   ├── getopt.c
│   │   │   │   │   ├── getopt1.c
│   │   │   │   │   ├── safe-ctype.c
│   │   │   │   │   ├── xexit.c
│   │   │   │   │   └── xstrdup.c
│   │   │   │   └── headers/
│   │   │   │       ├── ansidecl.h
│   │   │   │       ├── cp-demangle.h
│   │   │   │       ├── demangle.h
│   │   │   │       ├── dyn-string.h
│   │   │   │       ├── getopt.h
│   │   │   │       ├── libiberty.h
│   │   │   │       └── safe-ctype.h
│   │   │   └── demangler_gnu_v2_41/
│   │   │       ├── c/
│   │   │       │   ├── alloca.c
│   │   │       │   ├── argv.c
│   │   │       │   ├── cp-demangle.c
│   │   │       │   ├── cplus-dem.c
│   │   │       │   ├── cxxfilt.c
│   │   │       │   ├── d-demangle.c
│   │   │       │   ├── dyn-string.c
│   │   │       │   ├── getopt.c
│   │   │       │   ├── getopt1.c
│   │   │       │   ├── missing.c
│   │   │       │   ├── rust-demangle.c
│   │   │       │   ├── safe-ctype.c
│   │   │       │   ├── xexit.c
│   │   │       │   └── xstrdup.c
│   │   │       └── headers/
│   │   │           ├── ansidecl.h
│   │   │           ├── cp-demangle.h
│   │   │           ├── demangle.h
│   │   │           ├── dyn-string.h
│   │   │           ├── getopt.h
│   │   │           ├── libiberty.h
│   │   │           └── safe-ctype.h
│   │   └── build.gradle
│   ├── GnuDisassembler/
│   │   ├── data/
│   │   │   └── arm_test1.s
│   │   ├── src/
│   │   │   └── gdis/
│   │   │       └── c/
│   │   │           ├── disasm_1.c
│   │   │           └── gdis.h
│   │   ├── build.gradle
│   │   ├── buildGdis.gradle
│   │   └── settings.gradle
│   ├── nativeBuildProperties.gradle
│   ├── nativePlatforms.gradle
│   ├── settings.gradle
│   ├── utils.gradle
│   └── vsconfig.gradle
├── Ghidra/
│   ├── Configurations/
│   │   └── Public_Release/
│   │       └── build.gradle
│   ├── Debug/
│   │   ├── AnnotationValidator/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Debugger/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AddMapping.java
│   │   │   │   ├── ComputeUnwindInfoScript.java
│   │   │   │   ├── DemoDebuggerScript.java
│   │   │   │   ├── PopulateDemoTrace.java
│   │   │   │   └── RefreshRegistersScript.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── screen/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Debugger-agent-dbgeng/
│   │   │   ├── data/
│   │   │   │   └── support/
│   │   │   │       ├── kernel-dbgeng.py
│   │   │   │       ├── local-dbgeng-attach.py
│   │   │   │       ├── local-dbgeng-ext.py
│   │   │   │       ├── local-dbgeng-trace.py
│   │   │   │       ├── local-dbgeng.py
│   │   │   │       ├── remote-dbgeng.py
│   │   │   │       ├── standalone_listener.py
│   │   │   │       └── svrcx-dbgeng.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── py/
│   │   │   └── build.gradle
│   │   ├── Debugger-agent-drgn/
│   │   │   ├── data/
│   │   │   │   └── support/
│   │   │   │       └── local-drgn.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── py/
│   │   │   └── build.gradle
│   │   ├── Debugger-agent-gdb/
│   │   │   ├── data/
│   │   │   │   └── scripts/
│   │   │   │       └── remote-proc-mappings.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── py/
│   │   │   └── build.gradle
│   │   ├── Debugger-agent-lldb/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── py/
│   │   │   └── build.gradle
│   │   ├── Debugger-agent-x64dbg/
│   │   │   ├── data/
│   │   │   │   └── support/
│   │   │   │       ├── local-x64dbg-attach.py
│   │   │   │       └── local-x64dbg.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── py/
│   │   │   └── build.gradle
│   │   ├── Debugger-api/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Debugger-importers/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Debugger-isf/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Debugger-jpda/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       ├── java/
│   │   │   │       └── resources/
│   │   │   └── build.gradle
│   │   ├── Debugger-rmi-trace/
│   │   │   ├── data/
│   │   │   │   └── support/
│   │   │   │       ├── gmodutils.py
│   │   │   │       └── raw-python3.py
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── ConnectTraceRmiScript.java
│   │   │   │   ├── ListenTraceRmiScript.java
│   │   │   │   ├── RunBashInTerminalScript.java
│   │   │   │   └── TerminalGhidraScript.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   ├── java/
│   │   │   │   │   └── py/
│   │   │   │   └── screen/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Framework-TraceModeling/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── ProposedUtils/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   └── TaintAnalysis/
│   │       ├── src/
│   │       │   └── main/
│   │       │       └── java/
│   │       └── build.gradle
│   ├── Extensions/
│   │   ├── BSimElasticPlugin/
│   │   │   ├── src/
│   │   │   │   └── org/
│   │   │   │       └── elasticsearch/
│   │   │   ├── srcdummy/
│   │   │   │   └── org/
│   │   │   │       ├── apache/
│   │   │   │       └── elasticsearch/
│   │   │   └── build.gradle
│   │   ├── Jython/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AddCommentToProgramScriptPy.py
│   │   │   │   ├── AskScriptPy.py
│   │   │   │   ├── CallAnotherScriptForAllProgramsPy.py
│   │   │   │   ├── CallAnotherScriptPy.py
│   │   │   │   ├── ChooseDataTypeScriptPy.py
│   │   │   │   ├── ExampleColorScriptPy.py
│   │   │   │   ├── FormatExampleScriptPy.py
│   │   │   │   ├── ImportSymbolsScript.py
│   │   │   │   ├── PrintNonZeroPurge.py
│   │   │   │   ├── ToolPropertiesExampleScriptPy.py
│   │   │   │   ├── external_module_callee.py
│   │   │   │   ├── external_module_caller.py
│   │   │   │   ├── ghidra_basics.py
│   │   │   │   ├── jython_basics.py
│   │   │   │   └── python_basics.py
│   │   │   ├── jython-src/
│   │   │   │   ├── ghidradoc.py
│   │   │   │   ├── introspect.py
│   │   │   │   ├── jintrospect.py
│   │   │   │   └── sitecustomize.py
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Lisa/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── LisaLaunchScript.java
│   │   │   │   └── Lisa_ResolveX86orX64LinuxSyscallsScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── MachineLearning/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── FindFunctionsRFExampleScript.java
│   │   │   │   └── TurnOffFuncStartSearch.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SampleTablePlugin/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SleighDevTools/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── CompareSleighExternal.java
│   │   │   │   └── GNUDisassembleBlockScript.java
│   │   │   ├── pcodetest/
│   │   │   │   ├── c_src/
│   │   │   │   │   ├── arm/
│   │   │   │   │   ├── BIOPS2_BODY.c
│   │   │   │   │   ├── BIOPS4_BODY.c
│   │   │   │   │   ├── BIOPS_BODY.c
│   │   │   │   │   ├── BIOPS_DOUBLE_BODY.c
│   │   │   │   │   ├── BIOPS_FLOAT_BODY.c
│   │   │   │   │   ├── BIOPS_LONGLONG_BODY.c
│   │   │   │   │   ├── BitManipulation_BODY.c
│   │   │   │   │   ├── DecisionMaking_BODY.c
│   │   │   │   │   ├── GlobalVariables_BODY.c
│   │   │   │   │   ├── IterativeProcessingDoWhile_BODY.c
│   │   │   │   │   ├── IterativeProcessingFor_BODY.c
│   │   │   │   │   ├── IterativeProcessingWhile_BODY.c
│   │   │   │   │   ├── ParameterPassing1_BODY.c
│   │   │   │   │   ├── ParameterPassing2_BODY.c
│   │   │   │   │   ├── ParameterPassing3_BODY.c
│   │   │   │   │   ├── PointerManipulation_BODY.c
│   │   │   │   │   ├── StructUnionManipulation_BODY.c
│   │   │   │   │   ├── big_struct.h
│   │   │   │   │   ├── builtin.c
│   │   │   │   │   ├── misc_BODY.c
│   │   │   │   │   ├── pcode_test.c
│   │   │   │   │   ├── pcode_test.h
│   │   │   │   │   └── types.h
│   │   │   │   ├── build.py
│   │   │   │   ├── defaults.py
│   │   │   │   ├── pcode_defs.py
│   │   │   │   ├── pcodetest.py
│   │   │   │   └── tpp.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SymbolicSummaryZ3/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── bundle_examples/
│   │   │   ├── scripts_jar1/
│   │   │   │   └── org/
│   │   │   │       └── jarlib/
│   │   │   ├── scripts_jar2/
│   │   │   │   └── org/
│   │   │   │       └── jarlib/
│   │   │   ├── scripts_lib/
│   │   │   │   ├── org/
│   │   │   │   │   └── other/
│   │   │   │   └── IntraBundleExampleScript.java
│   │   │   ├── scripts_lib_user/
│   │   │   │   └── InterBundleExampleScript.java
│   │   │   ├── scripts_uses_jar/
│   │   │   │   └── UsesJarExampleScript.java
│   │   │   ├── scripts_uses_jar_version/
│   │   │   │   └── UsesJarByVersionExampleScript.java
│   │   │   ├── scripts_with_activator/
│   │   │   │   ├── internal/
│   │   │   │   │   └── MyActivator.java
│   │   │   │   └── ActivatorExampleScript.java
│   │   │   ├── scripts_with_manifest/
│   │   │   │   └── InterBundleManifestExampleScript.java
│   │   │   └── build.gradle
│   │   └── sample/
│   │       ├── src/
│   │       │   ├── main/
│   │       │   │   ├── help/
│   │       │   │   └── java/
│   │       │   └── test.slow/
│   │       │       └── java/
│   │       └── build.gradle
│   ├── Features/
│   │   ├── BSim/
│   │   │   ├── data/
│   │   │   │   ├── large_32.xml
│   │   │   │   ├── lshweights_32.xml
│   │   │   │   ├── lshweights_64.xml
│   │   │   │   ├── lshweights_64_32.xml
│   │   │   │   ├── lshweights_cpool.xml
│   │   │   │   ├── lshweights_nosize.xml
│   │   │   │   ├── medium_32.xml
│   │   │   │   ├── medium_64.xml
│   │   │   │   ├── medium_cpool.xml
│   │   │   │   ├── medium_nosize.xml
│   │   │   │   └── serverconfig.xml
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AddProgramToH2BSimDatabaseScript.java
│   │   │   │   ├── CompareBSimSignaturesScript.java
│   │   │   │   ├── CompareBSimSignaturesSpecifyWeightsScript.java
│   │   │   │   ├── CompareExecutablesScript.java
│   │   │   │   ├── CreateH2BSimDatabaseScript.java
│   │   │   │   ├── DumpBSimDebugSignaturesScript.java
│   │   │   │   ├── DumpBSimDebugSignaturesScript.py
│   │   │   │   ├── DumpBSimSignaturesScript.java
│   │   │   │   ├── DumpBSimSignaturesScript.py
│   │   │   │   ├── ExampleOverviewQueryScript.java
│   │   │   │   ├── ExampleOverviewQueryScript.py
│   │   │   │   ├── ExampleQueryClientScript.java
│   │   │   │   ├── GenerateSignatures.java
│   │   │   │   ├── GenerateSignatures.py
│   │   │   │   ├── LocalBSimQueryScript.java
│   │   │   │   ├── QueryFunction.java
│   │   │   │   ├── QueryFunction.py
│   │   │   │   ├── QueryWithFiltersScript.java
│   │   │   │   ├── SetExecutableCategoryScript.java
│   │   │   │   ├── TailoredAnalysis.java
│   │   │   │   └── UpdateBSimMetadata.java
│   │   │   ├── other/
│   │   │   │   └── testscripts/
│   │   │   │       ├── InstallMetadataTest.java
│   │   │   │       └── RegressionSignatures.java
│   │   │   ├── src/
│   │   │   │   ├── lshvector/
│   │   │   │   │   └── c/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   ├── java/
│   │   │   │   │   └── resources/
│   │   │   │   ├── screen/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── BSimFeatureVisualizer/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Base/
│   │   │   ├── data/
│   │   │   │   ├── typeinfo/
│   │   │   │   │   └── golang/
│   │   │   │   ├── functionTags.xml
│   │   │   │   ├── ms_pe_rich_products.xml
│   │   │   │   └── noReturnFunctionConstraints.xml
│   │   │   ├── developer_scripts/
│   │   │   │   ├── BuildResultState.java
│   │   │   │   ├── CleanupMergeDatabasesScript.java
│   │   │   │   ├── ConsistencyCheck.java
│   │   │   │   ├── FindInvalidFlowType.java
│   │   │   │   ├── FixLangId.java
│   │   │   │   ├── ForceRedisassembly.java
│   │   │   │   ├── GenerateBrandesKopfGraphScript.java
│   │   │   │   ├── GenerateTestGraphScript.java
│   │   │   │   ├── MoveMemoryRangeContents.java
│   │   │   │   ├── PopulateBigRepoScript.java
│   │   │   │   ├── RangeDisassemblerScript.java
│   │   │   │   ├── SummarizeAnalyzers.java
│   │   │   │   └── UpgradeTestProgramScript.java
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AddCommentToProgramScript.java
│   │   │   │   ├── AddReferencesInSwitchTable.java
│   │   │   │   ├── AddSingleReferenceInSwitchTable.java
│   │   │   │   ├── AddSourceFileScript.java
│   │   │   │   ├── AddSourceMapEntryScript.java
│   │   │   │   ├── AppleSingleDoubleScript.java
│   │   │   │   ├── ArmThumbFunctionTableScript.java
│   │   │   │   ├── AsciiToBinaryScript.java
│   │   │   │   ├── AskScript.java
│   │   │   │   ├── AskValuesExampleScript.java
│   │   │   │   ├── AssembleBlockScript.java
│   │   │   │   ├── AssembleCheckDevScript.java
│   │   │   │   ├── AssembleScript.java
│   │   │   │   ├── AssemblyThrasherDevScript.java
│   │   │   │   ├── AssociateExternalPELibrariesScript.java
│   │   │   │   ├── AutoRenameLabelsScript.java
│   │   │   │   ├── AutoRenameSimpleLabels.java
│   │   │   │   ├── BatchRename.java
│   │   │   │   ├── BatchSegregate64bit.java
│   │   │   │   ├── BinaryToAsciiScript.java
│   │   │   │   ├── BuildGhidraJarScript.java
│   │   │   │   ├── COFF_ArchiveScript.java
│   │   │   │   ├── COFF_Script.java
│   │   │   │   ├── CallAnotherScript.java
│   │   │   │   ├── CallAnotherScriptForAllPrograms.java
│   │   │   │   ├── CallotherCensusScript.java
│   │   │   │   ├── ChangeDataSettingsScript.java
│   │   │   │   ├── ChooseDataTypeScript.java
│   │   │   │   ├── ClearOrphanFunctions.java
│   │   │   │   ├── CompareAnalysisScript.java
│   │   │   │   ├── CompareGDTs.java
│   │   │   │   ├── ComputeCyclomaticComplexity.java
│   │   │   │   ├── CondenseAllRepeatingBytes.java
│   │   │   │   ├── CondenseFillerBytes.java
│   │   │   │   ├── CondenseRepeatingBytes.java
│   │   │   │   ├── CondenseRepeatingBytesAtEndOfMemory.java
│   │   │   │   ├── ConvertDotDotDotScript.java
│   │   │   │   ├── ConvertDotToDashInAutoAnalysisLabels.java
│   │   │   │   ├── CountAndSaveStrings.java
│   │   │   │   ├── CountSymbolsScript.java
│   │   │   │   ├── CreateDefaultGDTArchivesScript.java
│   │   │   │   ├── CreateEmptyProgramScript.java
│   │   │   │   ├── CreateExampleGDTArchiveScript.java
│   │   │   │   ├── CreateExportFileForDLL.java
│   │   │   │   ├── CreateFunctionAfterTerminals.java
│   │   │   │   ├── CreateFunctionsFromSelection.java
│   │   │   │   ├── CreateHelpTemplateScript.java
│   │   │   │   ├── CreateOperandReferencesInSelectionScript.java
│   │   │   │   ├── CreatePdbXmlFilesScript.java
│   │   │   │   ├── CreateRelocationBasedOperandReferences.java
│   │   │   │   ├── CreateStringScript.java
│   │   │   │   ├── CreateUEFIGDTArchivesScript.java
│   │   │   │   ├── DWARFLineInfoCommentScript.java
│   │   │   │   ├── DWARFLineInfoSourceMapScript.java
│   │   │   │   ├── DWARFMacroScript.java
│   │   │   │   ├── DWARFSetExternalDebugFilesLocationPrescript.java
│   │   │   │   ├── DebugSleighInstructionParse.java
│   │   │   │   ├── DeleteDeadDefaultPlatesScript.java
│   │   │   │   ├── DeleteEmptyPlateCommentsScript.java
│   │   │   │   ├── DeleteExitCommentsScript.java
│   │   │   │   ├── DeleteFunctionDefaultPlatesScript.java
│   │   │   │   ├── DeleteSpacePropertyScript.java
│   │   │   │   ├── DemangleAllScript.java
│   │   │   │   ├── DemangleSymbolScript.java
│   │   │   │   ├── DoARMDisassemble.java
│   │   │   │   ├── DoThumbDisassemble.java
│   │   │   │   ├── EditBytesScript.java
│   │   │   │   ├── EmbeddedFinderScript.java
│   │   │   │   ├── EmuX86DeobfuscateExampleScript.java
│   │   │   │   ├── EmuX86GccDeobfuscateHookExampleScript.java
│   │   │   │   ├── ExampleColorScript.java
│   │   │   │   ├── ExampleGraphServiceScript.java
│   │   │   │   ├── ExportFunctionInfoScript.java
│   │   │   │   ├── ExportImagesScript.java
│   │   │   │   ├── ExportProgramScript.java
│   │   │   │   ├── ExtractELFDebugFilesScript.java
│   │   │   │   ├── FFsBeGoneScript.java
│   │   │   │   ├── FindAndReplaceCommentScript.java
│   │   │   │   ├── FindAudioInProgramScript.java
│   │   │   │   ├── FindDataTypeConflictCauseScript.java
│   │   │   │   ├── FindDataTypeScript.java
│   │   │   │   ├── FindFunctionsUsingTOCinPEFScript.java
│   │   │   │   ├── FindImagesScript.java
│   │   │   │   ├── FindInstructionsNotInsideFunctionScript.java
│   │   │   │   ├── FindOverlappingCodeUnitsScript.java
│   │   │   │   ├── FindRunsOfPointersScript.java
│   │   │   │   ├── FindSharedReturnFunctionsScript.java
│   │   │   │   ├── FindTextScript.java
│   │   │   │   ├── FindUndefinedFunctionsFollowUpScript.java
│   │   │   │   ├── FindUndefinedFunctionsScript.java
│   │   │   │   ├── FindUnrecoveredSwitchesScript.java
│   │   │   │   ├── FindX86RelativeCallsScript.java
│   │   │   │   ├── FixArrayStructReferencesScript.java
│   │   │   │   ├── FixElfExternalOffsetDataRelocationScript.java
│   │   │   │   ├── FixOffcutInstructionScript.java
│   │   │   │   ├── FixOldSTVariableStorageScript.java
│   │   │   │   ├── Fix_ARM_Call_JumpsScript.java
│   │   │   │   ├── FixupCompositeDataTypesScript.java
│   │   │   │   ├── FixupGolangFuncParamStorageScript.java
│   │   │   │   ├── FixupNoReturnFunctionsNoRepairScript.java
│   │   │   │   ├── FixupNoReturnFunctionsScript.java
│   │   │   │   ├── FormatExampleScript.java
│   │   │   │   ├── GenerateLotsOfProgramsScript.java
│   │   │   │   ├── GenerateMaskedBitStringScript.java
│   │   │   │   ├── GeneratePrototypeTestFileScript.java
│   │   │   │   ├── GetAndSetAnalysisOptionsScript.java
│   │   │   │   ├── GraphClassesScript.java
│   │   │   │   ├── HelloWorldPopupScript.java
│   │   │   │   ├── HelloWorldScript.java
│   │   │   │   ├── ImportAllProgramsFromADirectoryScript.java
│   │   │   │   ├── ImportProgramScript.java
│   │   │   │   ├── InnerClassScript.java
│   │   │   │   ├── InstructionSearchScript.java
│   │   │   │   ├── IterateDataScript.java
│   │   │   │   ├── IterateFunctionsByAddressScript.java
│   │   │   │   ├── IterateFunctionsScript.java
│   │   │   │   ├── IterateInstructionsScript.java
│   │   │   │   ├── LabelDataScript.java
│   │   │   │   ├── LabelDirectFunctionReferencesScript.java
│   │   │   │   ├── LabelIndirectReferencesScript.java
│   │   │   │   ├── LabelIndirectStringReferencesScript.java
│   │   │   │   ├── LanguagesAPIDemoScript.java
│   │   │   │   ├── LinuxSystemMapImportScript.java
│   │   │   │   ├── LocateMemoryAddressesForFileOffset.java
│   │   │   │   ├── LocateMemoryAddressesForFileOffset.py
│   │   │   │   ├── MachO_Script.java
│   │   │   │   ├── MakeFunctionsInlineVoidScript.java
│   │   │   │   ├── MakeFunctionsScript.java
│   │   │   │   ├── MakeStackRefs.java
│   │   │   │   ├── MarkCallOtherPcode.java
│   │   │   │   ├── MarkUnimplementedPcode.java
│   │   │   │   ├── MarkupWallaceSrcScript.java
│   │   │   │   ├── Mips_Fix_T9_PositionIndependentCode.java
│   │   │   │   ├── MultiInstructionMemReference.java
│   │   │   │   ├── NameStringPointersPlus.java
│   │   │   │   ├── OpenSourceFileAtLineInEclipseScript.java
│   │   │   │   ├── OpenSourceFileAtLineInVSCodeScript.java
│   │   │   │   ├── Override_ARM_Call_JumpsScript.java
│   │   │   │   ├── PEF_script.java
│   │   │   │   ├── PE_script.java
│   │   │   │   ├── PasteCopiedListingBytesScript.java
│   │   │   │   ├── PortableExecutableRichPrintScript.java
│   │   │   │   ├── PrintFunctionCallTreesScript.java
│   │   │   │   ├── PrintStructureScript.java
│   │   │   │   ├── ProgressExampleScript.java
│   │   │   │   ├── PropagateConstantReferences.java
│   │   │   │   ├── PropagateExternalParametersScript.java
│   │   │   │   ├── PropagateX86ConstantReferences.java
│   │   │   │   ├── RecursiveStringFinder.py
│   │   │   │   ├── RegisterTouchesPerFunction.java
│   │   │   │   ├── ReloadSleighLanguage.java
│   │   │   │   ├── RemoveDeletedOverlayReferences.java
│   │   │   │   ├── RemoveSourceMapEntryScript.java
│   │   │   │   ├── RemoveSymbolQuotesScript.java
│   │   │   │   ├── RemoveUserCheckoutsScript.java
│   │   │   │   ├── RenameProgramsInProjectScript.java
│   │   │   │   ├── RenameStructMembers.java
│   │   │   │   ├── RenameVariable.java
│   │   │   │   ├── RepairDisassemblyScript.java
│   │   │   │   ├── RepairFuncDefinitionUsageScript.java
│   │   │   │   ├── ReplaceInComments.java
│   │   │   │   ├── ReportDisassemblyErrors.java
│   │   │   │   ├── ReportPercentDisassembled.java
│   │   │   │   ├── RepositoryFileUpgradeScript.java
│   │   │   │   ├── ResolveExternalReferences.java
│   │   │   │   ├── ResolveX86orX64LinuxSyscallsScript.java
│   │   │   │   ├── RunYARAFromGhidra.py
│   │   │   │   ├── SearchBaseExtended.java
│   │   │   │   ├── SearchForImageBaseOffsets.java
│   │   │   │   ├── SearchForImageBaseOffsetsScript.java
│   │   │   │   ├── SearchGuiMulti.java
│   │   │   │   ├── SearchGuiSingle.java
│   │   │   │   ├── SearchMemoryForStringsRegExScript.java
│   │   │   │   ├── SearchMnemonicsNoOpsNoConstScript.java
│   │   │   │   ├── SearchMnemonicsOpsConstScript.java
│   │   │   │   ├── SearchMnemonicsOpsNoConstScript.java
│   │   │   │   ├── SelectAddressesMappedToSourceFileScript.java
│   │   │   │   ├── SelectFunctionsScript.java
│   │   │   │   ├── SetEquateScript.java
│   │   │   │   ├── SetHeadlessContinuationOptionScript.java
│   │   │   │   ├── ShowEquatesInSelectionScript.java
│   │   │   │   ├── ShowSourceMapEntryStartsScript.java
│   │   │   │   ├── SplitMultiplePefContainersScript.java
│   │   │   │   ├── SplitUniversalBinariesScript.java
│   │   │   │   ├── SubsToFuncsScript.java
│   │   │   │   ├── SynchronizeGDTCategoryPaths.java
│   │   │   │   ├── TestPrototypeScript.java
│   │   │   │   ├── TranslateStringsScript.java
│   │   │   │   ├── TurnOffStackAnalysis.java
│   │   │   │   ├── VersionControl_AddAll.java
│   │   │   │   ├── VersionControl_ResetAll.java
│   │   │   │   ├── VersionControl_UndoAllCheckout.java
│   │   │   │   ├── VersionControl_VersionSummary.java
│   │   │   │   ├── XorMemoryScript.java
│   │   │   │   ├── YaraGhidraGUIScript.java
│   │   │   │   ├── ZapBCTRScript.java
│   │   │   │   └── mark_in_out.py
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── BytePatterns/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── DumpFunctionBitPatternInfoForCurrentFunctionScript.java
│   │   │   │   ├── DumpFunctionPatternInfoScript.java
│   │   │   │   ├── DumpMissedStarts.java
│   │   │   │   └── PatternStats.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── ByteViewer/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── CodeCompare/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── DataGraph/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── DebugUtils/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Decompiler/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── classrecovery/
│   │   │   │   │   ├── BaseTypeinfo.java
│   │   │   │   │   ├── DecompilerScriptUtils.java
│   │   │   │   │   ├── EditStructureUtils.java
│   │   │   │   │   ├── ExtendedFlatProgramAPI.java
│   │   │   │   │   ├── GccTypeinfo.java
│   │   │   │   │   ├── GccTypeinfoRef.java
│   │   │   │   │   ├── RTTIClassRecoverer.java
│   │   │   │   │   ├── RTTIGccClassRecoverer.java
│   │   │   │   │   ├── RTTIWindowsClassRecoverer.java
│   │   │   │   │   ├── RecoveredClass.java
│   │   │   │   │   ├── RecoveredClassHelper.java
│   │   │   │   │   ├── SpecialVtable.java
│   │   │   │   │   ├── Typeinfo.java
│   │   │   │   │   ├── TypeinfoRef.java
│   │   │   │   │   ├── Vftable.java
│   │   │   │   │   ├── Vtable.java
│   │   │   │   │   └── Vtt.java
│   │   │   │   ├── AddVfunctionCallRefScript.java
│   │   │   │   ├── ApplyClassFunctionDefinitionUpdatesScript.java
│   │   │   │   ├── ApplyClassFunctionSignatureUpdatesScript.java
│   │   │   │   ├── CompareFunctionSizesScript.java
│   │   │   │   ├── CreateStructure.java
│   │   │   │   ├── DecompilerStackProblemsFinderScript.java
│   │   │   │   ├── FindPotentialDecompilerProblems.java
│   │   │   │   ├── FixSwitchStatementsWithDecompiler.java
│   │   │   │   ├── GraphASTAndFlowScript.java
│   │   │   │   ├── GraphASTScript.java
│   │   │   │   ├── GraphSelectedASTScript.java
│   │   │   │   ├── RecoverClassesFromRTTIScript.java
│   │   │   │   ├── ShowCCallsScript.java
│   │   │   │   ├── ShowConstantUse.java
│   │   │   │   ├── StringParameterPropagator.java
│   │   │   │   ├── SwitchOverride.java
│   │   │   │   ├── TurnOnLanguage.java
│   │   │   │   └── WindowsResourceReference.java
│   │   │   ├── src/
│   │   │   │   ├── decompile/
│   │   │   │   │   ├── cpp/
│   │   │   │   │   ├── datatests/
│   │   │   │   │   ├── unittests/
│   │   │   │   │   ├── zlib/
│   │   │   │   │   └── build.gradle
│   │   │   │   ├── main/
│   │   │   │   │   ├── doc/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   ├── build.gradle
│   │   │   └── buildNatives.gradle
│   │   ├── DecompilerDependent/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── ExportPCodeForCTADL.java
│   │   │   │   ├── ExportPCodeForSingleFunction.java
│   │   │   │   └── ExportSourceSetScript.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── FileFormats/
│   │   │   ├── developer_scripts/
│   │   │   │   └── DexWriteRegistersScript.java
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── ApplyPEToDumpFileScript.java
│   │   │   │   ├── BTreeAnnotationScript.java
│   │   │   │   ├── BadInstructionCleanup.java
│   │   │   │   ├── GetSymbolForDynamicAddress.java
│   │   │   │   ├── MachoProcessBindScript.java
│   │   │   │   ├── MergeTwoProgramsScript.java
│   │   │   │   ├── PointerPullerScript.java
│   │   │   │   ├── RemoveAllOffcutReferencesScript.java
│   │   │   │   ├── RemoveOffcutReferenceToCurrentInstructionScript.java
│   │   │   │   ├── ResolveReferencesRelativeToEbxScript.java
│   │   │   │   ├── SplitExtensibleFirmwareInterfaceScript.java
│   │   │   │   └── ToolPropertiesExampleScript.java
│   │   │   ├── src/
│   │   │   │   ├── lzfse/
│   │   │   │   │   └── c/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   ├── build.gradle
│   │   │   └── buildNatives.gradle
│   │   ├── FunctionGraph/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── FunctionGraphDecompilerExtension/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── FunctionID/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AttachFidDatabase.java
│   │   │   │   ├── CollectFailedRelocations.java
│   │   │   │   ├── CreateEmptyFidDatabase.java
│   │   │   │   ├── CreateMultipleLibraries.java
│   │   │   │   ├── FIDHashCurrentFunction.java
│   │   │   │   ├── FidStatistics.java
│   │   │   │   ├── FindErrors.java
│   │   │   │   ├── FindFunctionByHash.java
│   │   │   │   ├── FindNamedFunction.java
│   │   │   │   ├── FunctionIDHeadlessPostscript.java
│   │   │   │   ├── FunctionIDHeadlessPrescript.java
│   │   │   │   ├── ImportMSLibs.java
│   │   │   │   ├── ListDomainFiles.java
│   │   │   │   ├── ListFunctions.java
│   │   │   │   ├── MSLibBatchImportGenerator.java
│   │   │   │   ├── MSLibBatchImportWorker.java
│   │   │   │   ├── RecursiveRecursiveMSLibImport.java
│   │   │   │   ├── RemoveFunctions.java
│   │   │   │   └── RepackFid.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── doc/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── screen/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── GhidraGo/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── GhidraServer/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── GnuDemangler/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── DemangleElfWithOptionScript.java
│   │   │   │   └── VxWorksSymTab_Finder.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── GraphFunctionCalls/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── screen/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── GraphServices/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── MicrosoftCodeAnalyzer/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── FixUpRttiAnalysisScript.java
│   │   │   │   ├── IdPeRttiScript.java
│   │   │   │   └── RunRttiAnalyzerScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── MicrosoftDemangler/
│   │   │   ├── developer_scripts/
│   │   │   │   └── MicrosoftDemanglerScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── MicrosoftDmang/
│   │   │   ├── developer_scripts/
│   │   │   │   ├── DeveloperDumpMDMangParseInfoScript.java
│   │   │   │   ├── MDMangDeveloperDemangleNamesScript.java
│   │   │   │   └── MDMangDeveloperGenericizeMangledNamesScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── PDB/
│   │   │   ├── developer_scripts/
│   │   │   │   ├── pdbquery/
│   │   │   │   │   ├── PdbFactory.java
│   │   │   │   │   └── PdbQuery.java
│   │   │   │   ├── CaptureHelperScript.java
│   │   │   │   ├── DeveloperDumpAllTypesScript.java
│   │   │   │   ├── DumpAllSymbolsDemangledScript.java
│   │   │   │   ├── PdbDeveloperApplyDummyScript.java
│   │   │   │   ├── PdbDeveloperDumpMangledSymbolNamesScript.java
│   │   │   │   ├── PdbDeveloperDumpMangledTypeNamesScript.java
│   │   │   │   ├── PdbDeveloperDumpScript.java
│   │   │   │   ├── PdbDeveloperDumpSetScript.java
│   │   │   │   ├── PdbExamplePrescript.java
│   │   │   │   ├── PdbQueryActivator.java
│   │   │   │   ├── PdbQueryCloseAllScript.java
│   │   │   │   ├── PdbQueryCloseScript.java
│   │   │   │   ├── PdbQueryDatatypeScript.java
│   │   │   │   ├── PdbQueryOpenScript.java
│   │   │   │   ├── PdbQuerySymbolScript.java
│   │   │   │   └── PdbSymbolServerExamplePrescript.java
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── GetMSDownloadLinkScript.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── pdb/
│   │   │   │       ├── cpp/
│   │   │   │       └── headers/
│   │   │   ├── build.gradle
│   │   │   └── buildNatives.gradle
│   │   ├── ProgramDiff/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── ProgramGraph/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── PyGhidra/
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── PyGhidraBasics.py
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   ├── java/
│   │   │   │   │   └── py/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   ├── support/
│   │   │   │   └── pyghidra_launcher.py
│   │   │   └── build.gradle
│   │   ├── Recognizers/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Sarif/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SourceCodeLookup/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SwiftDemangler/
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── SwiftDemanglerScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SystemEmulation/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── DebuggerEmuExampleScript.java
│   │   │   │   ├── DemoPcodeUseropLibrary.java
│   │   │   │   ├── DemoSyscallLibrary.java
│   │   │   │   ├── EmuDeskCheckScript.java
│   │   │   │   ├── StandAloneEmuExampleScript.java
│   │   │   │   ├── StandAloneStructuredSleighScript.java
│   │   │   │   └── StandAloneSyscallEmuExampleScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── VersionTracking/
│   │   │   ├── developer_scripts/
│   │   │   │   └── EvaluateVTMatch.java
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── AddVTSessionToVersionControl.java
│   │   │   │   ├── AutoVersionTrackingScript.java
│   │   │   │   ├── CreateAppliedExactMatchingSessionScript.java
│   │   │   │   ├── FindChangedFunctionsScript.java
│   │   │   │   ├── OpenVersionTrackingSessionScript.java
│   │   │   │   ├── OverrideFunctionPrototypesOnAcceptedMatchesScript.java
│   │   │   │   └── SetAutoVersionTrackingOptionsScript.java
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   ├── screen/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── VersionTrackingBSim/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── help/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   └── WildcardAssembler/
│   │       ├── ghidra_scripts/
│   │       │   ├── FindInstructionWithWildcard.java
│   │       │   └── WildSleighAssemblerInfo.java
│   │       ├── src/
│   │       │   └── main/
│   │       │       ├── help/
│   │       │       └── java/
│   │       └── build.gradle
│   ├── Framework/
│   │   ├── DB/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Docking/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Emulation/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── FileSystem/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Generic/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── java/
│   │   │   │       └── resources/
│   │   │   └── build.gradle
│   │   ├── Graph/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   ├── docs/
│   │   │   │   │   ├── help/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Gui/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Help/
│   │   │   ├── build.files/
│   │   │   │   └── buildLocalHelp.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Project/
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Pty/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       ├── java/
│   │   │   │       └── resources/
│   │   │   └── build.gradle
│   │   ├── SoftwareModeling/
│   │   │   ├── data/
│   │   │   │   └── charset_info.json
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   └── Utility/
│   │       ├── src/
│   │       │   └── main/
│   │       │       └── java/
│   │       └── build.gradle
│   ├── Processors/
│   │   ├── 6502/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── 6502.ldefs
│   │   │   │       ├── 6502.pspec
│   │   │   │       ├── 6502.slaspec
│   │   │   │       └── 65c02.slaspec
│   │   │   └── build.gradle
│   │   ├── 68000/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── 68000.ldefs
│   │   │   │   │   ├── 68000.pspec
│   │   │   │   │   ├── 68020.slaspec
│   │   │   │   │   ├── 68030.slaspec
│   │   │   │   │   ├── 68040.slaspec
│   │   │   │   │   └── coldfire.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── 68000_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── 8048/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── 8048.ldefs
│   │   │   │       ├── 8048.pspec
│   │   │   │       └── 8048.slaspec
│   │   │   └── build.gradle
│   │   ├── 8051/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── 80251.pspec
│   │   │   │       ├── 80251.slaspec
│   │   │   │       ├── 80390.slaspec
│   │   │   │       ├── 8051.ldefs
│   │   │   │       ├── 8051.pspec
│   │   │   │       ├── 8051.slaspec
│   │   │   │       ├── cip-51.slaspec
│   │   │   │       ├── mx51.pspec
│   │   │   │       └── mx51.slaspec
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── Update8051.java
│   │   │   └── build.gradle
│   │   ├── 8085/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── 8085.ldefs
│   │   │   │       ├── 8085.pspec
│   │   │   │       └── 8085.slaspec
│   │   │   └── build.gradle
│   │   ├── AARCH64/
│   │   │   ├── data/
│   │   │   │   ├── extensions/
│   │   │   │   │   └── objc/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── AARCH64.ldefs
│   │   │   │   │   ├── AARCH64.pspec
│   │   │   │   │   ├── AARCH64.slaspec
│   │   │   │   │   ├── AARCH64BE.slaspec
│   │   │   │   │   ├── AARCH64_AppleSilicon.slaspec
│   │   │   │   │   └── AppleSilicon.ldefs
│   │   │   │   ├── patterns/
│   │   │   │   │   ├── AARCH64_LE_patterns.xml
│   │   │   │   │   ├── AARCH64_win_patterns.xml
│   │   │   │   │   ├── patternconstraints.xml
│   │   │   │   │   └── prepatternconstraints.xml
│   │   │   │   └── aarch64-pltThunks.xml
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── ARM/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── ARM.ldefs
│   │   │   │   │   ├── ARM4_be.slaspec
│   │   │   │   │   ├── ARM4_le.slaspec
│   │   │   │   │   ├── ARM4t_be.slaspec
│   │   │   │   │   ├── ARM4t_le.slaspec
│   │   │   │   │   ├── ARM5_be.slaspec
│   │   │   │   │   ├── ARM5_le.slaspec
│   │   │   │   │   ├── ARM5t_be.slaspec
│   │   │   │   │   ├── ARM5t_le.slaspec
│   │   │   │   │   ├── ARM6_be.slaspec
│   │   │   │   │   ├── ARM6_le.slaspec
│   │   │   │   │   ├── ARM7_be.slaspec
│   │   │   │   │   ├── ARM7_le.slaspec
│   │   │   │   │   ├── ARM8_be.slaspec
│   │   │   │   │   ├── ARM8_le.slaspec
│   │   │   │   │   ├── ARM8m_be.slaspec
│   │   │   │   │   ├── ARM8m_le.slaspec
│   │   │   │   │   ├── ARMCortex.pspec
│   │   │   │   │   ├── ARM_v45.pspec
│   │   │   │   │   ├── ARMt.pspec
│   │   │   │   │   ├── ARMtTHUMB.pspec
│   │   │   │   │   ├── ARMt_v45.pspec
│   │   │   │   │   └── ARMt_v6.pspec
│   │   │   │   └── patterns/
│   │   │   │       ├── ARM_BE_patterns.xml
│   │   │   │       ├── ARM_LE_patterns.xml
│   │   │   │       ├── ARM_switch_patterns.xml
│   │   │   │       ├── patternconstraints.xml
│   │   │   │       └── prepatternconstraints.xml
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Atmel/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── atmega256.pspec
│   │   │   │   │   ├── avr32a.ldefs
│   │   │   │   │   ├── avr32a.pspec
│   │   │   │   │   ├── avr32a.slaspec
│   │   │   │   │   ├── avr8.ldefs
│   │   │   │   │   ├── avr8.pspec
│   │   │   │   │   ├── avr8.slaspec
│   │   │   │   │   ├── avr8e.slaspec
│   │   │   │   │   ├── avr8eind.slaspec
│   │   │   │   │   ├── avr8xmega.pspec
│   │   │   │   │   └── avr8xmega.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── AVR8_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── CreateAVR8GDTArchiveScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── BPF/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── BPF.ldefs
│   │   │   │       ├── BPF.pspec
│   │   │   │       └── BPF_le.slaspec
│   │   │   └── build.gradle
│   │   ├── CP1600/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── CP1600.ldefs
│   │   │   │       ├── CP1600.pspec
│   │   │   │       └── CP1600.slaspec
│   │   │   └── build.gradle
│   │   ├── CR16/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── CR16.ldefs
│   │   │   │       ├── CR16.pspec
│   │   │   │       ├── CR16B.slaspec
│   │   │   │       └── CR16C.slaspec
│   │   │   └── build.gradle
│   │   ├── DATA/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── data-be-64.slaspec
│   │   │   │       ├── data-le-64.slaspec
│   │   │   │       ├── data.ldefs
│   │   │   │       └── data.pspec
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── LoadDataScript.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Dalvik/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── Dalvik.ldefs
│   │   │   │       ├── Dalvik_Base.pspec
│   │   │   │       ├── Dalvik_Base.slaspec
│   │   │   │       ├── Dalvik_DEX_Android10.slaspec
│   │   │   │       ├── Dalvik_DEX_Android11.slaspec
│   │   │   │       ├── Dalvik_DEX_Android12.slaspec
│   │   │   │       ├── Dalvik_DEX_KitKat.slaspec
│   │   │   │       ├── Dalvik_DEX_Lollipop.slaspec
│   │   │   │       ├── Dalvik_DEX_Marshmallow.slaspec
│   │   │   │       ├── Dalvik_DEX_Nougat.slaspec
│   │   │   │       ├── Dalvik_DEX_Oreo.slaspec
│   │   │   │       ├── Dalvik_DEX_Pie.slaspec
│   │   │   │       └── Dalvik_ODEX_KitKat.slaspec
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── HCS08/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── HC05-M68HC05TB.pspec
│   │   │   │   │   ├── HC05.ldefs
│   │   │   │   │   ├── HC05.pspec
│   │   │   │   │   ├── HC05.slaspec
│   │   │   │   │   ├── HC08-MC68HC908QY4.pspec
│   │   │   │   │   ├── HC08.ldefs
│   │   │   │   │   ├── HC08.pspec
│   │   │   │   │   ├── HC08.slaspec
│   │   │   │   │   ├── HCS08-MC9S08GB60.pspec
│   │   │   │   │   ├── HCS08.ldefs
│   │   │   │   │   ├── HCS08.pspec
│   │   │   │   │   └── HCS08.slaspec
│   │   │   │   └── test-vectors/
│   │   │   │       ├── HC05_tv.s
│   │   │   │       ├── HC08_tv.s
│   │   │   │       └── HCS08_tv.s
│   │   │   └── build.gradle
│   │   ├── HCS12/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── HC12.pspec
│   │   │   │       ├── HC12.slaspec
│   │   │   │       ├── HCS12.ldefs
│   │   │   │       ├── HCS12.pspec
│   │   │   │       ├── HCS12.slaspec
│   │   │   │       ├── HCS12X.pspec
│   │   │   │       └── HCS12X.slaspec
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Hexagon/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── hexagon.ldefs
│   │   │   │   │   ├── hexagon.pspec
│   │   │   │   │   └── hexagon.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── Hexagon_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── developer_scripts/
│   │   │   │   └── VerifyHexagonTestVectors.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── JVM/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── JVM.ldefs
│   │   │   │       ├── JVM.pspec
│   │   │   │       └── JVM.slaspec
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── CreateJNIGDTArchivesScript.java
│   │   │   ├── resources/
│   │   │   │   ├── ArrayLengthTest.java
│   │   │   │   ├── ArrayTests.java
│   │   │   │   ├── BreakTest.java
│   │   │   │   ├── CheckCastTest.java
│   │   │   │   ├── Concat.java
│   │   │   │   ├── DoubleTests.java
│   │   │   │   ├── FloatTests.java
│   │   │   │   ├── ForEach.java
│   │   │   │   ├── GetPutFieldTest.java
│   │   │   │   ├── GetPutStaticTest.java
│   │   │   │   ├── IfTests.java
│   │   │   │   ├── InstanceOfTest.java
│   │   │   │   ├── InvokeDynamicTest.java
│   │   │   │   ├── InvokeInterfaceTest.java
│   │   │   │   ├── InvokeStatic.java
│   │   │   │   ├── InvokeVirtual.java
│   │   │   │   ├── InvokeVirtual1.java
│   │   │   │   ├── InvokeVirtual2.java
│   │   │   │   ├── JsrTest.java
│   │   │   │   ├── JsrTestRun.java
│   │   │   │   ├── LVALong.java
│   │   │   │   ├── LVALongTest1.java
│   │   │   │   ├── LVALongTestMinimal.java
│   │   │   │   ├── LdcTest.java
│   │   │   │   ├── LocalVariableTests.java
│   │   │   │   ├── LongReturnerTests.java
│   │   │   │   ├── LongTest.java
│   │   │   │   ├── LookupSwitchHex.java
│   │   │   │   ├── Methods.java
│   │   │   │   ├── MonitorTest.java
│   │   │   │   ├── MultiANewArrayTests.java
│   │   │   │   ├── MultipleConstructors.java
│   │   │   │   ├── NewTests.java
│   │   │   │   ├── NullTest.java
│   │   │   │   ├── RecursionTest.java
│   │   │   │   ├── ReturnTests.java
│   │   │   │   ├── StringTest.java
│   │   │   │   ├── TableSwitch.java
│   │   │   │   ├── Throw.java
│   │   │   │   ├── VarArgsTest.java
│   │   │   │   ├── WideInc.java
│   │   │   │   └── WideTest.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Loongarch/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── loongarch.ldefs
│   │   │   │   │   ├── loongarch32.pspec
│   │   │   │   │   ├── loongarch32_f32.slaspec
│   │   │   │   │   ├── loongarch32_f64.slaspec
│   │   │   │   │   ├── loongarch64.pspec
│   │   │   │   │   ├── loongarch64_f32.slaspec
│   │   │   │   │   └── loongarch64_f64.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── loongarch_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── M16C/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── M16C_60.ldefs
│   │   │   │       ├── M16C_60.pspec
│   │   │   │       ├── M16C_60.slaspec
│   │   │   │       ├── M16C_80.ldefs
│   │   │   │       ├── M16C_80.pspec
│   │   │   │       └── M16C_80.slaspec
│   │   │   └── build.gradle
│   │   ├── M8C/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── m8c.ldefs
│   │   │   │       ├── m8c.pspec
│   │   │   │       └── m8c.slaspec
│   │   │   └── build.gradle
│   │   ├── MC6800/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── 6800.ldefs
│   │   │   │       ├── 6805.ldefs
│   │   │   │       ├── 6805.pspec
│   │   │   │       ├── 6805.slaspec
│   │   │   │       ├── 6809.pspec
│   │   │   │       ├── 6809.slaspec
│   │   │   │       └── H6309.slaspec
│   │   │   └── build.gradle
│   │   ├── MCS96/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── MCS96.ldefs
│   │   │   │       ├── MCS96.pspec
│   │   │   │       └── MCS96.slaspec
│   │   │   └── build.gradle
│   │   ├── MIPS/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── mips.ldefs
│   │   │   │   │   ├── mips32.pspec
│   │   │   │   │   ├── mips32R6.pspec
│   │   │   │   │   ├── mips32R6be.slaspec
│   │   │   │   │   ├── mips32R6le.slaspec
│   │   │   │   │   ├── mips32be.slaspec
│   │   │   │   │   ├── mips32le.slaspec
│   │   │   │   │   ├── mips32micro.pspec
│   │   │   │   │   ├── mips64.pspec
│   │   │   │   │   ├── mips64R6.pspec
│   │   │   │   │   ├── mips64be.slaspec
│   │   │   │   │   ├── mips64le.slaspec
│   │   │   │   │   └── mips64micro.pspec
│   │   │   │   └── patterns/
│   │   │   │       ├── MIPS_BE_patterns.xml
│   │   │   │       ├── MIPS_LE_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   ├── main/
│   │   │   │   │   └── java/
│   │   │   │   └── test.slow/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── NDS32/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── nds32.ldefs
│   │   │   │   │   ├── nds32.pspec
│   │   │   │   │   ├── nds32be.slaspec
│   │   │   │   │   └── nds32le.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── nds32_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── PA-RISC/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── pa-risc.ldefs
│   │   │   │   │   ├── pa-risc32.pspec
│   │   │   │   │   └── pa-risc32be.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── pa-risc_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   └── build.gradle
│   │   ├── PIC/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── PIC24.ldefs
│   │   │   │       ├── PIC24.pspec
│   │   │   │       ├── PIC24E.slaspec
│   │   │   │       ├── PIC24F.slaspec
│   │   │   │       ├── PIC24H.slaspec
│   │   │   │       ├── dsPIC30F.slaspec
│   │   │   │       ├── dsPIC33C.slaspec
│   │   │   │       ├── dsPIC33E.slaspec
│   │   │   │       ├── dsPIC33F.slaspec
│   │   │   │       ├── pic12c5xx.ldefs
│   │   │   │       ├── pic12c5xx.pspec
│   │   │   │       ├── pic12c5xx.slaspec
│   │   │   │       ├── pic16.ldefs
│   │   │   │       ├── pic16.pspec
│   │   │   │       ├── pic16.slaspec
│   │   │   │       ├── pic16c5x.ldefs
│   │   │   │       ├── pic16c5x.pspec
│   │   │   │       ├── pic16c5x.slaspec
│   │   │   │       ├── pic16f.pspec
│   │   │   │       ├── pic16f.slaspec
│   │   │   │       ├── pic17c7xx.ldefs
│   │   │   │       ├── pic17c7xx.pspec
│   │   │   │       ├── pic17c7xx.slaspec
│   │   │   │       ├── pic18.ldefs
│   │   │   │       ├── pic18.pspec
│   │   │   │       └── pic18.slaspec
│   │   │   ├── ghidra_scripts/
│   │   │   │   └── CreatePICSwitch.java
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── PowerPC/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── ppc.ldefs
│   │   │   │   │   ├── ppc_32.pspec
│   │   │   │   │   ├── ppc_32_4xx_be.slaspec
│   │   │   │   │   ├── ppc_32_4xx_le.slaspec
│   │   │   │   │   ├── ppc_32_be.slaspec
│   │   │   │   │   ├── ppc_32_e500_be.slaspec
│   │   │   │   │   ├── ppc_32_e500_le.slaspec
│   │   │   │   │   ├── ppc_32_e500mc_be.slaspec
│   │   │   │   │   ├── ppc_32_e500mc_le.slaspec
│   │   │   │   │   ├── ppc_32_le.slaspec
│   │   │   │   │   ├── ppc_32_mpc8270.pspec
│   │   │   │   │   ├── ppc_32_quicciii_be.slaspec
│   │   │   │   │   ├── ppc_32_quicciii_le.slaspec
│   │   │   │   │   ├── ppc_64.pspec
│   │   │   │   │   ├── ppc_64_be.slaspec
│   │   │   │   │   ├── ppc_64_isa_altivec_be.slaspec
│   │   │   │   │   ├── ppc_64_isa_altivec_le.slaspec
│   │   │   │   │   ├── ppc_64_isa_altivec_vle_be.slaspec
│   │   │   │   │   ├── ppc_64_isa_be.slaspec
│   │   │   │   │   ├── ppc_64_isa_le.slaspec
│   │   │   │   │   ├── ppc_64_isa_vle_be.slaspec
│   │   │   │   │   └── ppc_64_le.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── PPC_BE_patterns.xml
│   │   │   │       ├── PPC_BE_prepatterns.xml
│   │   │   │       ├── PPC_LE_patterns.xml
│   │   │   │       ├── PPC_LE_prepatterns.xml
│   │   │   │       ├── patternconstraints.xml
│   │   │   │       └── prepatternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── RISCV/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── old/
│   │   │   │   │   ├── RV32.pspec
│   │   │   │   │   ├── RV64.pspec
│   │   │   │   │   ├── andestar_v5.ldefs
│   │   │   │   │   ├── andestar_v5.slaspec
│   │   │   │   │   ├── riscv.ilp32d.slaspec
│   │   │   │   │   ├── riscv.ldefs
│   │   │   │   │   └── riscv.lp64d.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── patternconstraints.xml
│   │   │   │       └── riscv_gc_patterns.xml
│   │   │   ├── scripts/
│   │   │   │   └── binutil.py
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Sparc/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── SparcV9.ldefs
│   │   │   │   │   ├── SparcV9.pspec
│   │   │   │   │   ├── SparcV9_32.slaspec
│   │   │   │   │   └── SparcV9_64.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── SPARC_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── SuperH/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── sh-1.slaspec
│   │   │   │       ├── sh-2.slaspec
│   │   │   │       ├── sh-2a.slaspec
│   │   │   │       ├── superh.ldefs
│   │   │   │       └── superh.pspec
│   │   │   └── build.gradle
│   │   ├── SuperH4/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── SuperH4.ldefs
│   │   │   │   │   ├── SuperH4.pspec
│   │   │   │   │   ├── SuperH4_be.slaspec
│   │   │   │   │   └── SuperH4_le.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── SuperH4_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── TI_MSP430/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── TI_MSP430.ldefs
│   │   │   │       ├── TI_MSP430.pspec
│   │   │   │       ├── TI_MSP430.slaspec
│   │   │   │       └── TI_MSP430X.slaspec
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Toy/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── toy.ldefs
│   │   │   │       ├── toy.pspec
│   │   │   │       ├── toy64_be.slaspec
│   │   │   │       ├── toy64_be_harvard.slaspec
│   │   │   │       ├── toy64_be_harvard_rev.slaspec
│   │   │   │       ├── toy64_le.slaspec
│   │   │   │       ├── toy_be.slaspec
│   │   │   │       ├── toy_be_posStack.slaspec
│   │   │   │       ├── toy_builder_be.slaspec
│   │   │   │       ├── toy_builder_be_align2.slaspec
│   │   │   │       ├── toy_builder_le.slaspec
│   │   │   │       ├── toy_builder_le_align2.slaspec
│   │   │   │       ├── toy_harvard.pspec
│   │   │   │       ├── toy_le.slaspec
│   │   │   │       ├── toy_wsz_be.slaspec
│   │   │   │       └── toy_wsz_le.slaspec
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── V850/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── V850.ldefs
│   │   │   │   │   ├── V850.pspec
│   │   │   │   │   └── V850.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── V850_patterns.xml
│   │   │   │       └── patternconstraints.xml
│   │   │   └── build.gradle
│   │   ├── Xtensa/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── xtensa.ldefs
│   │   │   │   │   ├── xtensa.pspec
│   │   │   │   │   ├── xtensa_be.slaspec
│   │   │   │   │   └── xtensa_le.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── patternconstraints.xml
│   │   │   │       └── xtensa_patterns.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── Z80/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── z180.pspec
│   │   │   │       ├── z180.slaspec
│   │   │   │       ├── z182.pspec
│   │   │   │       ├── z80.ldefs
│   │   │   │       ├── z80.pspec
│   │   │   │       ├── z80.slaspec
│   │   │   │       └── z8401x.pspec
│   │   │   ├── temp/
│   │   │   │   └── z8401x.pspec
│   │   │   └── build.gradle
│   │   ├── eBPF/
│   │   │   ├── data/
│   │   │   │   └── languages/
│   │   │   │       ├── eBPF.ldefs
│   │   │   │       ├── eBPF.pspec
│   │   │   │       ├── eBPF_be.slaspec
│   │   │   │       └── eBPF_le.slaspec
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   ├── tricore/
│   │   │   ├── data/
│   │   │   │   ├── languages/
│   │   │   │   │   ├── tc172x.pspec
│   │   │   │   │   ├── tc176x.pspec
│   │   │   │   │   ├── tc29x.pspec
│   │   │   │   │   ├── tricore.ldefs
│   │   │   │   │   ├── tricore.pspec
│   │   │   │   │   └── tricore.slaspec
│   │   │   │   └── patterns/
│   │   │   │       ├── patternconstraints.xml
│   │   │   │       └── tricore_patterns.xml
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   └── x86/
│   │       ├── data/
│   │       │   ├── extensions/
│   │       │   │   └── rust/
│   │       │   ├── languages/
│   │       │   │   ├── x86-16-real.pspec
│   │       │   │   ├── x86-16.pspec
│   │       │   │   ├── x86-64-compat32.pspec
│   │       │   │   ├── x86-64.pspec
│   │       │   │   ├── x86-64.slaspec
│   │       │   │   ├── x86.ldefs
│   │       │   │   ├── x86.pspec
│   │       │   │   └── x86.slaspec
│   │       │   └── patterns/
│   │       │       ├── patternconstraints.xml
│   │       │       ├── prepatternconstraints.xml
│   │       │       ├── x86-16_default_patterns.xml
│   │       │       ├── x86-64gcc_patterns.xml
│   │       │       ├── x86-64win_patterns.xml
│   │       │       ├── x86delphi_patterns.xml
│   │       │       ├── x86gcc_patterns.xml
│   │       │       ├── x86gcc_prepatterns.xml
│   │       │       ├── x86win_patterns.xml
│   │       │       └── x86win_prepatterns.xml
│   │       ├── src/
│   │       │   └── main/
│   │       │       └── java/
│   │       └── build.gradle
│   ├── RuntimeScripts/
│   │   ├── Common/
│   │   │   └── support/
│   │   │       ├── gradle/
│   │   │       │   ├── gradle-wrapper.jar
│   │   │       │   └── settings.gradle
│   │   │       ├── buildExtension.gradle
│   │   │       └── debug.log4j.xml
│   │   └── build.gradle
│   └── Test/
│       ├── DebuggerIntegrationTest/
│       │   ├── src/
│       │   │   ├── expCloneExec/
│       │   │   │   └── c/
│       │   │   ├── expCloneExit/
│       │   │   │   └── c/
│       │   │   ├── expCloneSpin/
│       │   │   │   └── c/
│       │   │   ├── expCreateProcess/
│       │   │   │   └── c/
│       │   │   ├── expCreateThreadExit/
│       │   │   │   └── c/
│       │   │   ├── expCreateThreadSpin/
│       │   │   │   └── c/
│       │   │   ├── expFork/
│       │   │   │   └── c/
│       │   │   ├── expPrint/
│       │   │   │   └── c/
│       │   │   ├── expRead/
│       │   │   │   └── c/
│       │   │   ├── expRegisters/
│       │   │   │   └── c/
│       │   │   ├── expSpin/
│       │   │   │   └── c/
│       │   │   ├── expStack/
│       │   │   │   └── c/
│       │   │   ├── expTraceableSleep/
│       │   │   │   └── c/
│       │   │   ├── screen/
│       │   │   │   └── java/
│       │   │   └── test.slow/
│       │   │       └── java/
│       │   └── build.gradle
│       ├── IntegrationTest/
│       │   ├── src/
│       │   │   ├── screen/
│       │   │   │   └── java/
│       │   │   └── test.slow/
│       │   │       └── java/
│       │   └── build.gradle
│       └── TestResources/
│           └── src/
│               └── cpp/
│                   ├── VersionTracking/
│                   ├── decomp/
│                   └── helloWorld/
├── GhidraBuild/
│   ├── BuildFiles/
│   │   ├── Doclets/
│   │   │   ├── src/
│   │   │   │   └── main/
│   │   │   │       └── java/
│   │   │   └── build.gradle
│   │   └── build.gradle
│   ├── EclipsePlugins/
│   │   ├── GhidraDev/
│   │   │   ├── GhidraDevFeature/
│   │   │   │   ├── build.gradle
│   │   │   │   ├── category.xml
│   │   │   │   └── feature.xml
│   │   │   └── GhidraDevPlugin/
│   │   │       ├── src/
│   │   │       │   └── main/
│   │   │       ├── build.gradle
│   │   │       └── plugin.xml
│   │   └── GhidraSleighEditor/
│   │       ├── ghidra.xtext.sleigh/
│   │       │   ├── src/
│   │       │   │   └── ghidra/
│   │       │   ├── build.gradle
│   │       │   └── plugin.xml
│   │       ├── ghidra.xtext.sleigh.feature/
│   │       │   ├── build.gradle
│   │       │   ├── category.xml
│   │       │   └── feature.xml
│   │       ├── ghidra.xtext.sleigh.ide/
│   │       │   └── build.gradle
│   │       ├── ghidra.xtext.sleigh.tests/
│   │       │   └── build.gradle
│   │       ├── ghidra.xtext.sleigh.ui/
│   │       │   ├── src/
│   │       │   │   └── ghidra/
│   │       │   ├── build.gradle
│   │       │   └── plugin.xml
│   │       └── ghidra.xtext.sleigh.ui.tests/
│   │           └── build.gradle
│   ├── IDAPro/
│   │   ├── Python/
│   │   │   ├── 6xx/
│   │   │   │   ├── loaders/
│   │   │   │   │   └── xmlldr.py
│   │   │   │   └── plugins/
│   │   │   │       └── xmlexp.py
│   │   │   ├── 7xx/
│   │   │   │   ├── loaders/
│   │   │   │   │   └── xml_loader.py
│   │   │   │   ├── plugins/
│   │   │   │   │   ├── xml_exporter.py
│   │   │   │   │   └── xml_importer.py
│   │   │   │   └── python/
│   │   │   │       └── idaxml.py
│   │   │   └── 9xx/
│   │   │       ├── loaders/
│   │   │       │   └── xml_loader.py
│   │   │       ├── plugins/
│   │   │       │   ├── xml_exporter.py
│   │   │       │   └── xml_importer.py
│   │   │       └── python/
│   │   │           └── idaxml.py
│   │   └── build.gradle
│   ├── LaunchSupport/
│   │   ├── src/
│   │   │   └── main/
│   │   │       └── java/
│   │   │           ├── ghidra/
│   │   │           └── LaunchSupport.java
│   │   └── build.gradle
│   ├── MarkdownSupport/
│   │   ├── src/
│   │   │   └── main/
│   │   │       └── java/
│   │   │           └── ghidra/
│   │   └── build.gradle
│   └── Skeleton/
│       ├── data/
│       │   ├── languages/
│       │   │   ├── skel.ldefs
│       │   │   ├── skel.pspec
│       │   │   └── skel.slaspec
│       │   └── buildLanguage.xml
│       ├── src/
│       │   └── main/
│       │       ├── help/
│       │       │   └── help/
│       │       └── java/
│       │           └── skeleton/
│       ├── build.gradle
│       └── buildTemplate.gradle
├── GhidraDocs/
│   ├── GhidraClass/
│   │   ├── Advanced/
│   │   │   └── src/
│   │   │       └── Examples/
│   │   │           ├── animals.cpp
│   │   │           ├── compilerVsDecompiler.s
│   │   │           ├── createStructure.c
│   │   │           ├── custom.c
│   │   │           ├── dataMutability.c
│   │   │           ├── globalRegVars.c
│   │   │           ├── inline.s
│   │   │           ├── jumpWithinInstruction.c
│   │   │           ├── ldiv.c
│   │   │           ├── noReturn.c
│   │   │           ├── opaque.c
│   │   │           ├── override.c
│   │   │           ├── setRegister.c
│   │   │           ├── sharedReturn.c
│   │   │           ├── switch.s
│   │   │           └── write.c
│   │   ├── AdvancedDevelopment/
│   │   │   ├── contrib/
│   │   │   │   └── gadc/
│   │   │   │       └── ghidra_scripts/
│   │   │   └── ghidra-format/
│   │   │       ├── body.c
│   │   │       ├── ghidra.h
│   │   │       └── main.c
│   │   ├── Debugger/
│   │   │   ├── ghidra_scripts/
│   │   │   │   ├── CustomLibraryScript.java
│   │   │   │   ├── DumpBoardScript.java
│   │   │   │   ├── InstallCustomLibraryScript.java
│   │   │   │   ├── InstallExprEmulatorScript.java
│   │   │   │   ├── ModelingScript.java
│   │   │   │   └── ZeroTimerScript.java
│   │   │   ├── gdb_syntax.xml
│   │   │   └── sleigh_syntax.xml
│   │   └── ExerciseFiles/
│   │       ├── Debugger/
│   │       │   ├── anyptracer.c
│   │       │   └── termmines.c
│   │       ├── Emulation/
│   │       │   └── Source/
│   │       │       ├── deobExample.c
│   │       │       └── deobHookExample.c
│   │       ├── VersionTracking/
│   │       │   └── Source/
│   │       │       ├── Mod1/
│   │       │       ├── Mod2/
│   │       │       └── Original/
│   │       └── WinhelloCPP/
│   │           └── source/
│   │               ├── Gadget.cpp
│   │               ├── Gadget.h
│   │               ├── Resource.h
│   │               ├── WinHelloCPP.cpp
│   │               ├── WinHelloCPP.h
│   │               ├── stdafx.cpp
│   │               └── stdafx.h
│   └── build.gradle
├── docker/
│   └── build.gradle
├── eclipse/
│   ├── GhidraCDTFormatter.xml
│   └── GhidraEclipseFormatter.xml
├── gradle/
│   ├── root/
│   │   ├── distribution.gradle
│   │   ├── eclipse.gradle
│   │   ├── jacoco.gradle
│   │   ├── prepDev.gradle
│   │   ├── svg.gradle
│   │   ├── test.gradle
│   │   ├── usage.gradle
│   │   └── venv.gradle
│   ├── support/
│   │   ├── distributionCommon.gradle
│   │   ├── extensionCommon.gradle
│   │   ├── fetchDependencies.gradle
│   │   ├── ip.gradle
│   │   ├── loadApplicationProperties.gradle
│   │   ├── sbom.gradle
│   │   ├── settingsUtil.gradle
│   │   └── testUtils.gradle
│   ├── distributableGPLExtension.gradle
│   ├── distributableGPLModule.gradle
│   ├── distributableGhidraExtension.gradle
│   ├── distributableGhidraModule.gradle
│   ├── externalGhidraExtension.gradle
│   ├── hasProtobuf.gradle
│   ├── hasPythonPackage.gradle
│   ├── helpProject.gradle
│   ├── jacocoProject.gradle
│   ├── javaProject.gradle
│   ├── javaTestProject.gradle
│   ├── javadoc.gradle
│   ├── nativeProject.gradle
│   └── processorProject.gradle
├── build.gradle
└── settings.gradle