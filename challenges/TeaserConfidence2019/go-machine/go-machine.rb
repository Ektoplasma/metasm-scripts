#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# Script for go-machine binary from reverse challenge of Teaser Confidence CTF 2019
# Inspired from DeliciousHorse solving script:
# https://github.com/DeliciousHorse/writeups/blob/master/TeaserConfidence2019/GoMachine/dump_vm_trace.py
# Just an attempt to do the same thing with Metasm


require 'metasm'
include Metasm
require 'pp'
require 'time'

@i = 0
@QWORD=8
@offset_sp_vm = 0x1398
@offset_top_vm = 0x13b0

@f = File.open("trace_#{Time.now.to_i}.s",'w')

def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
end

def showGui
    Metasm::Gui::DbgWindow.new(@dbg, "go-machine - metasm debugger")
    Gui.main
end

def get_imm(start, stop)
    ip = @dbg.get_reg_value("rax")
    bytecode = @dbg.get_reg_value("rbx")
    val = @dbg.memory[bytecode+ip+start, stop-start]
    #TODO: test conversion value
    val.to_i().to_s(16)
end

def Qword(s)
    s.unpack('Q*')[0]
end

def dump_stack
    rsp = @dbg.get_reg_value("rsp")
    stack_vm_addr = Qword(@dbg.memory[rsp+@offset_sp_vm,@QWORD])
    stack_vm_top = Qword(@dbg.memory[rsp+@offset_top_vm,@QWORD])
    dump = '('
    (0..stack_vm_top).each do |i|
      curdump = Qword(@dbg.memory[stack_vm_addr+i*@QWORD, @QWORD])
      dump += "0x#{curdump.to_s(16)} |"
    end
    dump += ')'
    
    dump
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

	  stck_dmp = dump_stack()
    decoded = ''
    case index
      when 0
        decoded += "sub\t"
      when 1
        decoded += "add\t"
      when 2
        decoded += "neg\t"
      when 3
        decoded += "mul\t"
      when 4
        decoded += "mod\t"
      when 5
        decoded += "push "
        num = get_imm(1, 0x15)
        decoded += "(0x" + num + ")\t"
      when 6
        decoded += "pop(ignore)\t"
      when 7
        decoded += "read_input\t"
      when 8
        decoded += "print_output\t"
      when 9
        decoded = "dup\t"
      when 0xA
        decoded += "save at "
        num = get_imm(1, 3)
        decoded += "(0x" + num + ")\t"
      when 0xB
        decoded += "load at "
        num = get_imm(1, 3)
        decoded += "(0x" + num + ")\t"
      when 0xC
        decoded += "pop to lower\t"
      when 0xD
        decoded += "shl\t"
      when 0xE
        decoded += "cmp\t"
      when 0xF
        decoded += "shuffle\t"
      else
          puts "Unhandled handler!"
    end

    decoded += stck_dmp
    @f.write("#{decoded}")
    @f.write("\n")
end

def start_32b
    @dbg.pass_current_exception
end

def debugloop

    @bp_startvm = @dbg.bpx(0x0487707, false){ dumpHandlers }
    #@dbg.bpx(0x04015cd, false){ exit }

    @dbg.callback_exception = lambda{ |e| start_32b()}
    
    @dbg.run_forever
    @f.close
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
