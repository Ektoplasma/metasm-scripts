# encoding: ASCII-8BIT
require 'metasm'
include Metasm

file = ARGV.shift
pe = PE.decode_file(file)

@dasm = pe.disassembler
@dasm.disassemble_fast_deep 'entrypoint'

@dasm.disassemble_fast 'entrypoint'
@dasm.decoded.each{|addr,di|
    puts di.to_s
}
