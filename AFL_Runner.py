#-------------------------------------------------------------------------------
# Name:        AFL_Runner
# Purpose:     starts afl-fuzz.exe with provided parameters. configure it once.
#              makes running easy in case afl-fuzz.exe crahses, you dont need
#              to type entire command and parameters. jsut run AFL_Runner.py
# arguments:  if AFLDebug = 1 then it will first run drrun.exe in debug mode and
#               generate a log file. open that log file and check if everything
#               is working fine. if you dont give this arg, then it will start
#               afl-fuzz.exe with configured parameters.
# how to run:   1. run AFL_Runner.py --AFLDebug 1 from winafl\bin32 dir. 
#               and check log file. if everything is fine then go to step 2.
#                2. run AFL_Runner.py and enjoy fuzzing.
# Author:      hardik shah
#
# Created:     03/06/2019
# Copyright:   (c) hardik shah 2019
# twitter: @hardik05
# Licence:     GNU GPLV3
#-------------------------------------------------------------------------------
import os
import argparse

'''
default options - no need to change unless you really want to try some different values
'''
AFL_FUZZ_EXE = "afl-fuzz.exe"
FUZZ_ITERATIONS  = "5000"
COVTYPE = "edge" #edge is supposed to give better output then block
TIMEOUT = "5000+"

'''
specific options - change them to suit you needs
'''
DYNAMORIO_BIN32_DIR ="D:\\Research\\WinAFL_Work\\DynamoRIO-Windows-7.1.0-1\\bin32" #enter path to dynamorio bin32/64 dir
FUZZ_EXE_NAME = "test_gdiplus.exe" #harness or program you want to fuzz
FUZZ_OFFSET_OR_METHOD = "0x1680" # enter offset of the fuzz function if symbol is not available or simply enter function name if symbols are available.
NARGS = "2" #number of arguments herness takes.
CALL_CONVENTION = "stdcall" # this can be any of the following value-> stdcall,thiscall,ms64,fastcall
COVERAGE_MODULES_NAMES = {"gdiplus.dll","windowscodecs.dll"} #enter the dll files you want to instrument
CORPUS_INPUT_DIR = "InGDI"  #folder containing input test cases
OUTPUT_DIR = "OutGDI" #folder containing output ->crashes,hangs and other afl specific data

'''
DO NOT CHANGE ANYTHING BELOW
'''
AFL_FUZZ_OPTIONS = "-i " + CORPUS_INPUT_DIR + " -o " + OUTPUT_DIR + " -t " + TIMEOUT + " -D " + DYNAMORIO_BIN32_DIR
WINAFL_OPTIONS = ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--AFLDebug", help="Runs AFL in debug mode and check if everything is working as expected.")
    args = parser.parse_args()
    #print(args.AFLDebug)
    if(args.AFLDebug):
        DRPATH = DYNAMORIO_BIN32_DIR + "\\drrun.exe" + " -c winafl.dll -debug -target_module " + FUZZ_EXE_NAME
        if "0x" in FUZZ_OFFSET_OR_METHOD:
            DRPATH = DRPATH + " -target_offset " + FUZZ_OFFSET_OR_METHOD
        else:
            DRPATH = DRPATH + " -target_method " + FUZZ_OFFSET_OR_METHOD
        DRPATH = DRPATH + " -fuzz_iterations 10" + " -nargs " + NARGS  + " -- " + FUZZ_EXE_NAME + " @@"
        print DRPATH
        os.system("cmd.exe /c start " + DRPATH)
    else:
        COVERAGE_MODULE =""
        for name in COVERAGE_MODULES_NAMES:
            COVERAGE_MODULE = COVERAGE_MODULE + "-coverage_module " + name + " "

        WINAFL_OPTIONS = COVERAGE_MODULE + "-target_module " + FUZZ_EXE_NAME
        if "0x" in FUZZ_OFFSET_OR_METHOD:
            WINAFL_OPTIONS = WINAFL_OPTIONS + " -target_offset " + FUZZ_OFFSET_OR_METHOD
        else:
            WINAFL_OPTIONS = WINAFL_OPTIONS + " -target_method " + FUZZ_OFFSET_OR_METHOD
        WINAFL_OPTIONS = WINAFL_OPTIONS +" -fuzz_iterations " + FUZZ_ITERATIONS + " -call_convention " + CALL_CONVENTION + " -nargs " + NARGS + " -covtype " + COVTYPE
        FINAL_COMMAND_LINE = AFL_FUZZ_EXE + " " +  AFL_FUZZ_OPTIONS + " -- " + WINAFL_OPTIONS + " -- " + FUZZ_EXE_NAME + " @@"
        #print FINAL_COMMAND_LINE
        os.system("cmd.exe /c start " + FINAL_COMMAND_LINE)

if __name__ == '__main__':
    main()
