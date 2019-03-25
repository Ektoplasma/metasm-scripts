# encoding: ASCII-8BIT
require 'metasm'
require 'pp'
include Metasm

file = ARGV.shift
pe = PE.decode_file(file)

@dasm = pe.disassembler
@dasm.disassemble_fast_deep 'entrypoint'

binary = open(file, "rb") {|io| io.read }.force_encoding("ASCII-8BIT")

@dasm.decoded.each{|addr,di|
    # puts di.to_s
    if di.opcode.name =~ /(mov|lea)/
        list_dest_current = []
        @dasm.get_fwdemu_binding(di).each{|dest,exp|
            list_dest_current << dest
        }
        list_dest_next = []
        same_src_dst = false
        ndi = @dasm.di_at(addr+di.bin_length)
        if ndi != nil and ndi.opcode.name =~ /(mov|lea)/
            @dasm.get_fwdemu_binding(ndi).each{|dest,exp|
                list_dest_current.each{|cdest|
                    if exp.to_s =~ /#{cdest.to_s.gsub('[',"\\[").gsub(']',"\\]")}/
                        same_src_dst = true
                    end
                }
                list_dest_next << dest
            }
            if list_dest_current == list_dest_next and same_src_dst == false
                offset_to_nop = pe.addr_to_fileoff(addr)
                puts "TO NOP : #{di} #{offset_to_nop}"
                binary[offset_to_nop,di.bin_length] = "\x90" * di.bin_length
            end
        end
    end
}

open(file+"_noped.exe", "wb") {|io| io.write(binary) }