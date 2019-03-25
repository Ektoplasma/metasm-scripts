# encoding: ASCII-8BIT
require 'metasm'
require 'pp'
include Metasm

file = ARGV.shift
pe = PE.decode_file(file)

@dasm = pe.disassembler
@dasm.disassemble_fast_deep 'entrypoint'

@dasm.decoded.each{|addr,di|
    puts di.to_s
    @dasm.get_fwdemu_binding(di).each{|dest,exp|
        resolv = @dasm.backtrace(exp,di.address)[0]
        nres = @dasm.normalize(resolv)
        if nres.to_s =~ /^[0-9]+$/
            puts "  #{dest} = #{nres.to_s(16)}"
        end
    }
}
