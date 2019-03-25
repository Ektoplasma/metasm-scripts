# encoding: ASCII-8BIT
require 'metasm'
include Metasm

file = ARGV.shift
pe = PE.decode_file(file)

binary = open(file, "rb") {|io| io.read }.force_encoding("ASCII-8BIT")
open(file+"_noped.exe", "wb") {|io| io.write(binary)}

@dasm = pe.disassembler
@dasm.disassemble_fast_deep 0x401530

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



