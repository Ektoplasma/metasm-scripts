#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'

@i = 0

def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
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

    #ajouter switch case des handlers 
end

def start_32b
    @dbg.pass_current_exception
end

def debugloop

    @bp_startvm = @dbg.bpx(0x0487707, false){ dumpHandlers }
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
