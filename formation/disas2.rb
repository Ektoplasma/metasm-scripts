# encoding: ASCII-8BIT
require 'metasm'
include Metasm

file = ARGV.shift
pe = PE.decode_file(file)

@dasm = pe.disassembler
@dasm.disassemble_fast_deep 'entrypoint'

@dasm.disassemble_fast 'entrypoint'
@dasm.decoded.each{|addr,di|
    
    if di.opcode.name == 'cmp'
        arg1 = di.instruction.args[0].to_s
        arg2 = di.instruction.args[1].to_s
        if arg2.length < 3
            arg2 = arg1
        end
        di.block.list.each{|cdi|
            if di.address != cdi.address
                if cdi.instruction.to_s =~ /(#{arg1.gsub('[',"\\[").gsub(']',"\\]")}|#{arg2.gsub('[',"\\[").gsub(']',"\\]")})/
                    puts cdi.to_s
                end
            end
        }
        puts di.to_s
        puts "-------"
    end
}
