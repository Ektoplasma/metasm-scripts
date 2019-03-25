#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'

file = ARGV.shift

@pr = OS.current.create_process(file)
@dbg = @pr.debugger
@dasm = @dbg.disassembler
@verbose = true

def hook_IsDbgPresent()
    puts "IsDebuggerPresent"
end

def hook_ChkRemoteDbgPresent()
    puts "CheckRemoteDebuggerPresent"
end

def hook_GetProcessHeap()
    puts "GetProcessHeap"
end

def hook_GetCurrentProcess()
    puts "GetCurrentProcess"
end

def hook_CloseHandle()
    puts "CloseHandle"
end

def hook_OutputDebugStringA()
    puts "OutputDebugStringA"
end

def hook_AddVectoredExceptionHandler()
    puts "AddVectoredExceptionHandler"
end

def hook_RemoveVectoredExceptionHandler()
    puts "RemoveVectoredExceptionHandler"
end

def GetAddress(modulename, funcname)
    results = []
    @dbg.symbols.each{|m|
        if m[1].casecmp(funcname) == 0
            results << m
        end
    }
    @dbg.modulemap.each{|module_name, module_addr|
        if module_name.casecmp(modulename) == 0
            results.each{|addr, name|
                if addr >= module_addr[0] and addr <= module_addr[1]
                    puts "    [*] #{funcname} is at 0x#{addr.to_s(16)}" if @verbose == true
                    return addr
                end
            }
        end
    }
    0
end

def start_32b()
    getCurrentProcess_addr = GetAddress("kernelbase.dll","GetCurrentProcess")
    if getCurrentProcess_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(getCurrentProcess_addr, false) { hook_GetCurrentProcess() }
    end
    isDbgPresent_addr = GetAddress("kernelbase.dll","IsDebuggerPresent")
    if isDbgPresent_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(isDbgPresent_addr, false) { hook_IsDbgPresent() }
    end
    chkRemoteDbgPresent_addr = GetAddress("kernelbase.dll","CheckRemoteDebuggerPresent")
    if chkRemoteDbgPresent_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(chkRemoteDbgPresent_addr, false) { hook_ChkRemoteDbgPresent() }
    end
    getProcessHeap_addr = GetAddress("kernelbase.dll","GetProcessHeap")
    if getProcessHeap_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(getProcessHeap_addr, false) { hook_GetProcessHeap() }
    end
    closeHandle_addr = GetAddress("kernelbase.dll","CloseHandle")
    if closeHandle_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(closeHandle_addr, false) { hook_CloseHandle() }
    end
    outputDebugStringA_addr = GetAddress("kernelbase.dll","OutputDebugStringA")
    if outputDebugStringA_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(outputDebugStringA_addr, false) { hook_OutputDebugStringA() }
    end
    addVectoredExceptionHandler_addr = GetAddress("kernelbase.dll","AddVectoredExceptionHandler")
    if addVectoredExceptionHandler_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(addVectoredExceptionHandler_addr, false) { hook_AddVectoredExceptionHandler() }
    end
    removeVectoredExceptionHandler_addr = GetAddress("kernelbase.dll","RemoveVectoredExceptionHandler")
    if removeVectoredExceptionHandler_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(removeVectoredExceptionHandler_addr, false) { hook_RemoveVectoredExceptionHandler() }
    end
    @dbg.pass_current_exception
end

@dbg.callback_exception = lambda{ |e| start_32b()}
@dbg.run_forever