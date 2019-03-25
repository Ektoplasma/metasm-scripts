#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'

file = ARGV.shift

@pr = OS.current.create_process(file)
@dbg = @pr.debugger
@dasm = @dbg.disassembler

@jumper = 0x040A37f
@start = 0x040A1C0

def hook_VirtualAlloc()
    puts "Hey !"
end

def bp_jumper()
    puts "Hoy"
    dasm.normalize()
    dump = LoadPE.memdump @dbg.memory,
    @baseaddr,@oep, @iat
    start_32b()
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

def show_gui()
    Gui::DbgWindow.new(@dbg, "Debgging")
    Gui.main
end

def start_32b()
    virtualAlloc_addr = GetAddress("kernelbase.dll","IsDebuggerPresent")
    if virtualAlloc_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(virtualAlloc_addr, false) { hook_VirtualAlloc() }
    end
    @dbg.pass_current_exception
end

@dbg.bpx(@jumper, false) { bp_jumper() }

@dbg.callback_exception = lambda{ |e| start_32b()}
@dbg.run_forever
#004014E0