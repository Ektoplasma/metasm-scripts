# encoding: ASCII-8BIT
require 'metasm'
include Metasm

def next_di(di)
    ndi = @dasm.di_at(addr+di.bin_length)
end

def prev_di(di)
    ndi = @dasm.di_at(addr-di.bin_length)
end

def burn_di(di, addr)
    offset_to_nop = pe.addr_to_fileoff(addr)
    puts "TO NOP : #{di} #{offset_to_nop}"
    binary[offset_to_nop,di.bin_length] = "\x90" * di.bin_length
end

def replace_di(di)
    ndi = @dasm.di_at(addr+di.bin_length)
end