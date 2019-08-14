#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:		Crash_Analyzer.py
# Purpose: analyzes crashes and stores them in OUTPUT_DIR according to crash
#           function name. also generate a details.txt file containing details
#           about the crash.
#
# Author:	  hardik shah
# email:    hardik05@gmail.com
# web:      http://hardik05.wordpress.com
# Created:	 20/07/2019
# Copyright:   (c) hardik shah 2019
# Licence:	 GNU GPL
#-------------------------------------------------------------------------------
import os,sys,shutil,re
from winappdbg import Crash,win32,Debug,System
from datetime import datetime
from time import time

PROGRAM_PATH = "E:\\fuzzing_work\\Application_which_crash.exe" #application path
INPUT_DIR = "E:\\fuzzing_work\\input\\" #input dir containing testcase
OUTPUT_DIR = "E:\\fuzzing_work\\output" #output dir
EXT_TO_IGNORE = {".txt",".js",".zip"} #file ext to ignore
TestCaseName = ""
filepath = ""
does_crash = False

# Add some colouring, not working in this version. :(
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

def DebugProgram(filepath):
	#Instance a Debug object.
	debug_args = list()
	debug_args.insert(0,PROGRAM_PATH)
	debug_args.insert(len(debug_args),filepath)

	debug = Debug(AccessViolationHandlerWINAPPDBG, bKillOnExit = True)
	#debug.system.load_dbghelp("C:\\Program Files\\Debugging Tools for Windows (x86)\\dbghelp.dll")
	System.fix_symbol_store_path(symbol_store_path = "C:\\ProgramData\\Dbg\\sym",remote = True,force = True) #enter local symbol path here if you have downloaded symbols
	System.set_kill_on_exit_mode(True)
	try:
		 # The execution time limit is 5 seconds.
		maxTime = time() + 5
		# Start a new process for debugging.
		debug.execv(debug_args)

		# Wait for the debugee to finish.
		#debug.loop()
		 # Loop while calc.exe is alive and the time limit wasn't reached.
		while debug and time() < maxTime:
			try:

				# Get the next debug event.
				debug.wait(1000)  # 1 second accuracy

				# Show the current time on screen.
				#print time()

			# If wait() times out just try again.
			# On any other error stop debugging.
			except WindowsError, e:
				if e.winerror in (win32.ERROR_SEM_TIMEOUT,
								  win32.WAIT_TIMEOUT):
					continue
				raise

			# Dispatch the event and continue execution.
			try:
				debug.dispatch()
			finally:
				debug.cont()
		# Stop the debugger.
	finally:
		debug.stop()

def AccessViolationHandlerWINAPPDBG(event):

		# Handle access violation while using winappdbg
#todo: correct error codes
# hardik
		code = event.get_event_code()
		if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
			global does_crash
			does_crash = True
			crash = Crash(event)
			crash.fetch_extra_data(event)
			details =r"""
			  _____
			 / ____|			 | |	   /\			   | |						 /_ | / _ \
			| |	 _ __ __ _ ___| |__	/  \   _ __   __ _| |_   _ _______ _ __  __   _| || | | |
			| |	| '__/ _` / __| '_ \  / /\ \ | '_ \ / _` | | | | |_  / _ \ '__| \ \ / / || | | |
			| |____| | | (_| \__ \ | | |/ ____ \| | | | (_| | | |_| |/ /  __/ |	 \ V /| || |_| |
			 \_____|_|  \__,_|___/_| |_/_/	\_\_| |_|\__,_|_|\__, /___\___|_|	  \_/ |_(_)___/
																__/ |
															   |___/
			email: hardik05@gmail.com
			web: http://hardik05.wordpress.com
			"""
			details = details + "\r\n" + crash.fullReport(bShowNotes=True)
			violation_addr = hex(crash.registers['Eip'])
			label = crash.labelPC
			Crash_Function_Name = label.split('+')[0]
			Crash_Function_Name = re.sub('[^A-Za-z0-9]+', '_', Crash_Function_Name)
			thetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
			exe_name =  event.get_process().get_filename().split('\\')[-1]
			#crashfilename is the file containing the crash details
			crashfilename = 'crash_'+TestCaseName+'_'+'_'+ thetime
			#syncfilename is the file containig crash details
			synfilename = OUTPUT_DIR + '\\crashes\\'+exe_name+'\\'+ Crash_Function_Name +'\\crash_'+ TestCaseName + '_details.txt' + '_' + thetime + ".txt"
			if not os.path.exists(OUTPUT_DIR + '\\crashes\\'+exe_name):
				os.makedirs(OUTPUT_DIR + '\\crashes\\'+exe_name)
			if not os.path.exists(OUTPUT_DIR + '\\crashes\\'+exe_name+'\\'+Crash_Function_Name):
				os.makedirs(OUTPUT_DIR + '\\crashes\\'+exe_name+'\\'+Crash_Function_Name)
			syn = open(synfilename,'w+')
			syn.write(details)
			syn.close()
   #print '[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S")+' Killing half dead process'
			try:
				event.get_process().kill()
				shutil.move(filepath,OUTPUT_DIR + '\\crashes\\'+exe_name+'\\'+Crash_Function_Name+'\\'+crashfilename)
				print RED + 'Program is crashing at :'+ END, Crash_Function_Name
				print 'Crash file moved to : ', (OUTPUT_DIR + '\\crashes\\'+ exe_name+'\\'+Crash_Function_Name+'\\'+crashfilename)
			except:
				print "error"


def main():
   	if not os.path.exists(OUTPUT_DIR + '\\notcrashing\\'):
		os.makedirs(OUTPUT_DIR + '\\notcrashing\\')
	for r, d, f in os.walk(INPUT_DIR):
		for file in f:
			ext_matched = False
			for ext in EXT_TO_IGNORE:
				if ext  in file:
					ext_matched = True
					break
				else:
					continue
			if ext_matched == False :
				global does_crash
				does_crash = False
				global TestCaseName
				TestCaseName = file
				global filepath
				filepath = os.path.join(r, file)
				print "\r\n\r\n"
				print(YELLOW + filepath + END)
				DebugProgram(filepath)
				if does_crash == False:
					print "file:" + filepath + " does not crash."
					thetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
					not_crashfilename = 'crash_'+file+'_'+'_'+ thetime
					shutil.move(filepath,OUTPUT_DIR + '\\notcrashing\\'+ not_crashfilename)


if __name__ == '__main__':
	main()
