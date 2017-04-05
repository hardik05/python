## Pythin script to hook various APIs
##Author: Hardik Shah
##Mail: hardik05@gmail.com

#"C:\Program Files\Microsoft Office\Office16\winword.exe"

from pydbg import *
from pydbg.defines import *
import pydasm

import utils
import binascii
import sys
import os
import struct
from ctypes import *
from optparse import OptionParser

is_hook = 0

def DissemAt(dbg, add):
    print "dissembly:"
    for i in dbg.disasm_around(add):
            print "0x%08x  %s" % i
    return

def GetArgFromMemory(dbg,arg):
    offset=0
    buffer=""
    while 1:
            byte = dbg.read_process_memory( arg + offset, 2 )
            if not ( ord(byte[0])==0 and ord(byte[1])==0) :
                buffer  += byte
                offset  += 2
                continue
            else:
                break
    return buffer
########################################################################################################################
#scan for rop/shellcode instructions

def VirtualProtectHook( dbg, args ):
    buffer  = ""

    offset_ThirdParam =dbg.context.Esp + 12
    byteProtect = dbg.read_process_memory( offset_ThirdParam, 4 )
    byteProtect=struct.unpack("L",byteProtect)[0]

    offset_SecondParam =dbg.context.Esp + 8
    byteSize = dbg.read_process_memory( offset_SecondParam, 4 )
    byteSize=struct.unpack("L",byteSize)[0]
    #print "Size is:",hex(byte)

    #check the protect is atlease execute and size is > 256 bytes then only we display message
    #we ignore the smaller size as the assumption is that shellcode should be greater then atleast 256 bytes if it calls virtualprotect
    if (byteProtect == 0x40 or byteProtect == 0x10 or byteProtect == 0x20 or byteProtect==0x80) and (byteSize > 0x100):
        print "########################################################################################################################"
        print "found virtualprotect call with protect:",hex(byteProtect)
        print "Size is:",hex(byteSize)
        offset_ReturnAddress  = dbg.context.Esp
        byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
        byte=struct.unpack("L",byte)[0]
        print "RET address:",hex(byte)
        DissemAt(dbg,byte)
        #for i in dbg.disasm_around(byte):
            #print "0x%08x  %s" % i
        modname = dbg.addr_to_module(byte).szModule
        print "modname:",modname

        offset_firstParam  = dbg.context.Esp + 4
        byte = dbg.read_process_memory( offset_firstParam, 4 )
        byte=struct.unpack("L",byte)[0]
        print "Address is:",hex(byte)
##        if byte!= 0x00000000:
##            DissemAt(dbg,byte)
##        else:
##            print "address is not given"
        print "########################################################################################################################"

##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE

########################################################################################################################

def VirtualProtectHookEx( dbg, args ):
    buffer  = ""

    offset_ThirdParam =dbg.context.Esp + 16
    byteProtect = dbg.read_process_memory( offset_ThirdParam, 4 )
    byteProtect=struct.unpack("L",byteProtect)[0]

    offset_SecondParam =dbg.context.Esp + 12
    byteSize = dbg.read_process_memory( offset_SecondParam, 4 )
    byteSize=struct.unpack("L",byteSize)[0]
    #print "Size is:",hex(byte)

    #check the protect is atlease execute and size is > 256 bytes then only we display message
    #we ignore the smaller size as the assumption is that shellcode should be greater then atleast 256 bytes if it calls virtualprotect
    if (byteProtect == 0x40 or byteProtect == 0x10 or byteProtect == 0x20 or byteProtect==0x80) and (byteSize > 0x100):
        print "########################################################################################################################"
        print "found virtualprotectEx call with protect:",hex(byteProtect)
        print "Size is:",hex(byteSize)
        offset_ReturnAddress  = dbg.context.Esp
        byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
        byte=struct.unpack("L",byte)[0]
        print "RET address:",hex(byte)
        DissemAt(dbg,byte)
        modname = dbg.addr_to_module(byte).szModule
        print "modname:",modname

        offset_firstParam  = dbg.context.Esp + 8
        byte = dbg.read_process_memory( offset_firstParam, 4 )
        byte=struct.unpack("L",byte)[0]
        print "Address is:",hex(byte)
##        if byte!= 0x00000000:
##            DissemAt(dbg,byte)
##        else:
##            print "address is not given"
        print "########################################################################################################################"
##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE

########################################################################################################################

########################################################################################################################
#to do dissemble bytes at the address
#scan for rop/shellcode instructions

def VirtualAllocHook( dbg, args ):
    print "########################################################################################################################"
    print "VirtualAlloc Called:"
    offset_ReturnAddress  = dbg.context.Esp
    byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
    byte=struct.unpack("L",byte)[0]
    print "RET address:",hex(byte)
    DissemAt(dbg,byte)
    print "Address:",hex(args[0])
    print "Size:",hex(args[1])
##    if args[0]!= 0x00000000:
##        DissemAt(dbg,byte)
##    else:
##        print "address is not given"
    print "########################################################################################################################"

##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE

########################################################################################################################

def CreateFileAHook( dbg, args ):
    buffer  = ""
    #args1 will have file attribut, we can add check later to display only file with generic_write access for shellcode deection purpose

    #print hex(args[1])
    if args[1] == 0x80000000 or args[1] == 0xC0000000:
        print "########################################################################################################################"
        offset  = 0

        offset_ReturnAddress  = dbg.context.Esp
        byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
        byte=struct.unpack("L",byte)[0]
        print "RET address:",hex(byte)
        DissemAt(dbg,byte)
        modname = dbg.addr_to_module(byte).szModule
        print "modname:",modname

        while 1:
            byte = dbg.read_process_memory( args[0] + offset, 2 )
            if not ( ord(byte[0])==0 and ord(byte[1])==0) :
                buffer  += byte
                offset  += 2
                continue
            else:
                break
        print "CreateFileA FileName:",buffer
        print "########################################################################################################################"
##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE
########################################################################################################################

def CreateFileWHook( dbg, args ):
    buffer  = ""
    #args1 will have file attribut, we can add check later to display only file with generic_write access for shellcode deection purpose

    #print hex(args[1])
    if args[1] == 0x80000000 or args[1] == 0xC0000000:
        print "########################################################################################################################"
        offset  = 0

        offset_ReturnAddress  = dbg.context.Esp
        byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
        byte=struct.unpack("L",byte)[0]
        print "RET address:",hex(byte)
        DissemAt(dbg,byte)
        modname = dbg.addr_to_module(byte).szModule
        print "modname:",modname

        while 1:
            byte = dbg.read_process_memory( args[0] + offset, 2 )
            if not ( ord(byte[0])==0 and ord(byte[1])==0) :
                buffer  += byte
                offset  += 2
                continue
            else:
                break
        print "CreateFileW FileName:",unicode(buffer,"utf-16")
        print "########################################################################################################################"

##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE
########################################################################################################################

def CreateProcessAHook( dbg, args ):
    buffer  = ""
    #args1 will have file attribut, we can add check later to display only file with generic_write access for shellcode deection purpose

    #print hex(args[1])

    print "########################################################################################################################"
    offset  = 0

    offset_ReturnAddress  = dbg.context.Esp
    byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
    byte=struct.unpack("L",byte)[0]
    print "RET address:",hex(byte)
    DissemAt(dbg,byte)
    modname = dbg.addr_to_module(byte).szModule
    print "modname:",modname

    print "CreateProcessW FileName:",args[0]
    print "CreateProcessW CmdLine:",args[1]
    print "########################################################################################################################"

##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE
########################################################################################################################

def CreateProcessWHook( dbg, args ):
    buffer  = ""
    #args1 will have file attribut, we can add check later to display only file with generic_write access for shellcode deection purpose

    #print hex(args[1])

    print "########################################################################################################################"
    offset  = 0

    offset_ReturnAddress  = dbg.context.Esp
    byte = dbg.read_process_memory( offset_ReturnAddress, 4 )
    byte=struct.unpack("L",byte)[0]
    print "RET address:",hex(byte)
    DissemAt(dbg,byte)
    modname = dbg.addr_to_module(byte).szModule
    print "modname:",modname

    print "CreateProcessW FileName:",unicode(GetArgFromMemory(dbg,args[0]),"utf-16")
    print "CreateProcessW CmdLine:",unicode(GetArgFromMemory(dbg,args[1]),"utf-16")
    print "########################################################################################################################"

##    byte = dbg.read_process_memory( args[1] + offset, 4 )
##    print "Size is:",binascii.hexlify(byte)
    return DBG_CONTINUE
########################################################################################################################


def load_dll (pydbg):
    last_dll = pydbg.system_dlls[-1]
    #print "loading:%s into:%08x size:%d" % (last_dll.name, last_dll.base, last_dll.size)
    global is_hook
    #print "in loaddll"
    if is_hook==0 :
#todo add createprocess and urldownload hooks
        global hooks
        hooks = utils.hook_container()
        hook_address_virtualprotect  = pydbg.func_resolve_debuggee("kernel32.dll","VirtualProtect")
        hook_address_virtualprotectEx  = pydbg.func_resolve_debuggee("kernel32.dll","VirtualProtectEx")
        hook_address_VirtualAlloc  = pydbg.func_resolve_debuggee("kernel32.dll","VirtualAlloc")
        hook_address_CreateFileA  = pydbg.func_resolve_debuggee("kernel32.dll","CreateFileA")
        hook_address_CreateFileW  = pydbg.func_resolve_debuggee("kernel32.dll","CreateFileW")
        hook_address_CreateProcessA  = pydbg.func_resolve_debuggee("kernel32.dll","CreateProcessA")
        hook_address_CreateProcessW  = pydbg.func_resolve_debuggee("kernel32.dll","CreateProcessW")

        #print hook_address_virtualprotect

        if hook_address_virtualprotect:
            res = hooks.add( pydbg, hook_address_virtualprotect, 4, VirtualProtectHook, None)
            is_hook =1
            print res
            print "[*] VirtualProtect hooked at: 0x%08x" % hook_address_virtualprotect
        else:
            print "[*] Error: Couldn't resolve virtualProtect address."

        if hook_address_virtualprotectEx:
            res = hooks.add( pydbg, hook_address_virtualprotectEx, 5, VirtualProtectHookEx, None)
            is_hook =1
            print res
            print "[*] VirtualProtectEx hooked at: 0x%08x" % hook_address_virtualprotectEx
        else:
            print "[*] Error: Couldn't resolve virtualProtectEx address."

        if hook_address_VirtualAlloc:
            res = hooks.add( pydbg, hook_address_VirtualAlloc, 4, VirtualAllocHook, None)
            is_hook =1
            print res
            print "[*] VirtualAlloc hooked at: 0x%08x" % hook_address_VirtualAlloc
        else:
            print "[*] Error: Couldn't resolve virtualAlloc address."

        if hook_address_CreateFileA:
            res = hooks.add( pydbg, hook_address_CreateFileA, 7, CreateFileAHook, None)
            is_hook =1
            print res
            print "[*] CreateFileA hooked at: 0x%08x" % hook_address_CreateFileA
        else:
            print "[*] Error: Couldn't resolve CreateFileA address."

        if hook_address_CreateFileW:
            res = hooks.add( pydbg, hook_address_CreateFileW, 7, CreateFileWHook, None)
            is_hook =1
            print res
            print "[*] CreateFileW hooked at: 0x%08x" % hook_address_CreateFileW
        else:
            print "[*] Error: Couldn't resolve CreateFileW address."

        if hook_address_CreateProcessA:
            res = hooks.add( pydbg, hook_address_CreateProcessA, 7, CreateProcessAHook, None)
            is_hook =1
            print res
            print "[*] CreateProcessA hooked at: 0x%08x" % hook_address_CreateProcessA
        else:
            print "[*] Error: Couldn't resolve CreateProcessA address."

        if hook_address_CreateProcessW:
            res = hooks.add( pydbg, hook_address_CreateProcessW, 7, CreateProcessWHook, None)
            is_hook =1
            print res
            print "[*] CreateProcessW hooked at: 0x%08x" % hook_address_CreateProcessW
        else:
            print "[*] Error: Couldn't resolve CreateProcessW address."

    return DBG_CONTINUE


# This is our access violation handler
def check_accessv(dbg):
      # We skip first-chance exceptions
      if dbg.dbg.u.Exception.dwFirstChance:
        return DBG_EXCEPTION_NOT_HANDLED
      crash_bin = utils.crash_binning.crash_binning()
      crash_bin.record_crash(dbg)
      print crash_bin.crash_synopsis()
      dbg.terminate_process()
      return DBG_EXCEPTION_NOT_HANDLED


def main():
     print("=======================================================================\r\n")
     print("HookAPIs - A tool to hook and monitor various parameter passed to APIs\r\n")
     print("Author: Hardik Shah\r\n")
     print("Mail: Hardik05@gmail.com\r\n")
     print("=======================================================================\r\n")
     parser = OptionParser()
     parser.add_option("-i", "--pid", dest="pid",
                  help="pid of the process you want to hook", metavar="PID")
     parser.add_option("-n", "--pname", dest="pname",
                  help="name of the process you want to hook", metavar="PNAME")
     parser.add_option("-f", "--fpath", dest="fpath",
                  help="path of the executable you want to hook", metavar="FPATH")
     (options, args) = parser.parse_args()
     if not options.pid and not options.pname and not options.fpath:
        parser.error('no argument given')
        sys.exit(2)


     dbg = pydbg()

     if options.pid:
        print"attaching to pid:", int(options.pid)
        dbg.attach(int(options.pid))
        dbg.set_callback(LOAD_DLL_DEBUG_EVENT, load_dll)
     elif options.pname:
        for pid,name in dbg.enumerate_processes():
            if name==options.pname:
                print "attaching to pid:",pid,name
                dbg.attach(pid)
                dbg.set_callback(LOAD_DLL_DEBUG_EVENT, load_dll)
                break
     elif options.fpath:
        print "loading and attaching to executable:",options.fpath
        dbg.set_callback(LOAD_DLL_DEBUG_EVENT, load_dll)
        dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,check_accessv) #Create the callback for the exception access violation
        dbg.load(options.fpath)

     #dbg.set_callback(LOAD_DLL_DEBUG_EVENT, load_dll)
     is_hook =0
     hooks=None

     dbg.debug_event_loop()


if __name__ == '__main__':
    main()
