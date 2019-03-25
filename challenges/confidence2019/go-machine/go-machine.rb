#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'

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
    Metasm::Gui::DbgWindow.new(@dbg, "go-machine - metasm debugger")
    Gui.main
end

def dumpHandlers
    stack_p = @dbg.get_reg_value("rsp")
    handler_str = @dbg.memory[stack_p + 0x48,16]
    instr = @dbg.get_reg_value("rsi") & 0xFF
    instr = instr.chr
    index = handler_str.index(instr)
    puts "RSP:\t0x#{stack_p.to_s(16)}"
    puts "instr:\t#{instr}"
    puts "handlet_str:\t#{handler_str}"
    puts "index:\t#{index}"
end

def start_32b
    @dbg.pass_current_exception
end

def debugloop

    @dbg.bpx(0x0487707, false){ dumpHandlers }
    #@dbg.bpx(0x04015cd, false){ exit }

    @dbg.callback_exception = lambda{ |e| start_32b()}
    
    @dbg.run_forever
    puts 'done'
    
	
end


file = ARGV.shift

puts '#################################################'
puts '####  Tracing go-machine vm handlers'
puts '#################################################'
elf = LoadedELF.decode_file(file)
@ori_elf = elf
@baseaddr = elf.load_address

entrypoints = []
entrypoints << 'entrypoint'
@dasm = elf.disassemble_fast_deep 'entrypoint'

@dbg = LinDebugger.new(file)

puts 'running...'
debugloop
