#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'

@disass_output_addr = 0x0043c470
@f = File.open('shellcode.s','w')

@i = 0

def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
end

def hook_bfWriteProcessMemory
    write_pmem_child = @pr.memory[@dbg.ctx[:esp], 0x10]
    out = bin_to_hex write_pmem_child
    hProcess = write_pmem_child[0,4].unpack('L')[0]
    child_target_addr = write_pmem_child[4,4].unpack('L')[0]
    new_instr_addr = write_pmem_child[8,4].unpack('L')[0]
    new_instr_length = write_pmem_child[12,4].unpack('L')[0]

    puts "new_instr_addr:0x#{"%x" % new_instr_addr}"
    puts "new_instr_length:0x#{"%x" % new_instr_length}"

    disass_output = @pr.memory[@disass_output_addr,256]
    disass_output = disass_output.split "\x00"
    disass_output = disass_output[0]

    new_instr = @pr.memory[new_instr_addr,new_instr_length]
    puts "  [*] Disas to be written: #{disass_output}"

    @f.write("#{@i}:     #{disass_output}")
    @f.write("\n")

    @i = @i + 1
    
end

def showGui
    Metasm::Gui::DbgWindow.new(@dbg, "#{@pr.pid} - metasm debugger")
    Gui.main
end

def start_32b
    @dbg.pass_current_exception
end

def debugloop
    # set up a oneshot breakpoint on oep
    @iat = 0xffffffff

    @dbg.bpx(0x004020AA, false){ hook_bfWriteProcessMemory() }

    @dbg.bpx(0x04015cd, false){ exit }

    @dbg.callback_exception = lambda{ |e| start_32b()}
    
    @dbg.run_forever
    puts 'done'
    
	
end

def buildIAT_callback
    if @dbg.ctx[:ebx] < (@iat + @dbg.os_process.modules[0].addr)
        @iat = @dbg.ctx[:ebx] - @dbg.os_process.modules[0].addr
        puts "    [*] IAT address set at 0x#{@iat.to_s(16)}"
    end
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

def isInModules(addr)
    @dbg.modulemap.each{|module_name, module_addr|
        if addr >= module_addr[0] and addr <= module_addr[1]
            return true
        end
    }
    return false
end

def isInPE(addr)
    if addr >= @dbg.os_process.modules[0].addr and addr <= (@dbg.os_process.modules[0].addr+@dbg.os_process.modules[0].size)
        return true
    end
    return false
end

file = ARGV.shift

puts '#################################################'
puts '####  Fetching watchmen.exe nanomites shellcode'
puts '#################################################'
pe = PE.decode_file(file)
@ori_pe = pe
@baseaddr = pe.optheader.image_base

entrypoints = []
entrypoints << 'entrypoint'
@dasm = pe.disassemble_fast_deep 'entrypoint'
@pr = OS.current.create_process(file)
@dbg = @pr.debugger

puts 'running...'
debugloop
