# encoding: ASCII-8BIT
require 'metasm'
require 'pp'
include Metasm

file = ARGV.shift
addr_entry = ARGV.shift
@file = file
pe = PE.decode_file(file)
@pe = pe
@dasm = pe.disassembler
puts "[*] Disassemble in process..."
blocks_done = []
if addr_entry != nil
    @dasm.disassemble_fast_deep addr_entry.to_i(0)
else
    @dasm.disassemble_fast_deep 'entrypoint'
end

@new_file_raw = open(file, "rb") {|io| io.read }.force_encoding("ASCII-8BIT")
@new_file = {}

# pp @dasm.methods
if pe.header.machine == "AMD64"
    @registers_identification = {/(al|ah|ax|eax|rax)/=>:rax,/(bl|bh|bx|ebx|rbx)/=>:rbx,/(cl|ch|cx|ecx|rcx)/=>:rcx,/(dl|dh|dx|edx|rdx)/=>:rdx,/(bp|ebp|rbp)/=>:rbp,/(sp|esp|rsp)/=>:rsp,/(si|esi|rsi)/=>:rsi,/(di|edi|rdi)/=>:rdi,/(r8)/=>:r8,/(r9)/=>:r9,/(r10)/=>:r10,/(r11)/=>:r11,/(r12)/=>:r12,/(r13)/=>:r13,/(r14)/=>:r14,/(r15)/=>:r15}
else
    @registers_identification = {/(al|ah|ax|eax|rax)/=>:eax,/(bl|bh|bx|ebx|rbx)/=>:ebx,/(cl|ch|cx|ecx|rcx)/=>:ecx,/(dl|dh|dx|edx|rdx)/=>:edx,/(bp|ebp|rbp)/=>:ebp,/(sp|esp|rsp)/=>:esp,/(si|esi|rsi)/=>:esi,/(di|edi|rdi)/=>:edi}
end

# pp Shellcode.assemble(Ia32.new, "mov eax, 0x31313131").encoded.data


def next_di(di)
    ndi = @dasm.di_at(di.address + di.bin_length)
    return ndi
end

def prev_di(di)
    for i in 1..15
        pdi = @dasm.di_at(di.address - i)
        if pdi != nil and pdi.bin_length == i
            return pdi
        end
    end
    return nil
end

def write_in_new_file_from_addr(address, datas)
    offset = @pe.addr_to_fileoff(address)
    for i in 0..(datas.length-1)
        @new_file[offset+i] = datas[i]
    end
end

def write_in_new_file_from_offset(offset, datas)
    for i in 0..(datas.length-1)
        @new_file[offset+i] = datas[i]
    end
end

def burn_di(di)
    write_in_new_file_from_addr(di.address, "\x90" * di.bin_length)
end

def replace_di(di, new_instr, force = false)
    if @pe.header.machine == "AMD64"
        encode_instr = Shellcode.assemble(AMD64.new, new_instr).encoded.data
    else
        encode_instr = Shellcode.assemble(Ia32.new, new_instr).encoded.data
    end
    if encode_instr != nil and (encode_instr.length <= di.bin_length or force == true)
        burn_di(di)
        write_in_new_file_from_addr(di.address, encode_instr)
        return true
    end
    return false
end

def get_dest(di)
    @registers_identification.each{|check,reg|
        if di.instruction.args[0].to_s =~ check
            return reg
        end
    }
    return nil
end

def is_optim_instr(di)
    optim_instrs = ['mov','add','sub','xor','lea']
    if optim_instrs.include?(di.opcode.name) and not(di.instruction.to_s.include?('[')) and @dasm.normalize(di.instruction.args[1]).to_s =~ /^[0-9]+$/
        return get_dest(di)
    end
    if di.opcode.name == 'lea'
        # pp di.to_s
        @dasm.get_fwdemu_binding(di).each{|reg,exp|
            if @dasm.normalize(exp).to_s =~ /^[0-9]+$/
                return reg
            end
        }
    end
    return nil
end

def get_regs_in_di(di)
    list_deref = []
    if di.opcode.name =~ /(sto|movs)/
        if @pe.header.machine == "AMD64"
            list_deref = [:rcx,:rsi,:rdi]
        else
            list_deref = [:ecx,:esi,:edi]
        end
    end
    @registers_identification.each{|check,reg|
        di.instruction.args.each{|carg|
            if carg.to_s =~ check and not(list_deref.include?(reg))
                list_deref << reg
            end
        }
    }
    return list_deref
end

def solve_optim(di_list)
    arg = 0
    instr_name = di_list[0].opcode.name
    if di_list[0].opcode.name == 'mov'
        arg = @dasm.normalize(di_list[0].instruction.args[1])
    end
    if di_list[0].opcode.name == 'lea'
        arg = @dasm.normalize(@dasm.get_fwdemu_binding(di_list[0]).first[1])
        instr_name = 'mov'
    end
    if di_list[0].opcode.name == 'sub'
        arg -= @dasm.normalize(di_list[0].instruction.args[1])
    end
    if di_list[0].opcode.name == 'add'
        arg += @dasm.normalize(di_list[0].instruction.args[1])
    end
    
    if di_list[1].opcode.name == 'sub'
        arg -= @dasm.normalize(di_list[1].instruction.args[1])
        arg = arg & 0xffffffff
    end
    if di_list[1].opcode.name == 'add'
        arg += @dasm.normalize(di_list[1].instruction.args[1])
        arg = arg & 0xffffffff
    end
    if di_list[1].opcode.name == 'xor'
        arg ^= @dasm.normalize(di_list[1].instruction.args[1])
        arg = arg & 0xffffffff
    end
    if di_list[1].opcode.name == 'mov'
        arg = @dasm.normalize(di_list[1].instruction.args[1])
    end
    if replace_di(di_list[0], "#{instr_name} #{di_list[0].instruction.args[0]}, 0x#{arg.to_s(16)}") == true
        puts "    [*] Replace successfull : #{instr_name} #{di_list[0].instruction.args[0]}, 0x#{arg.to_s(16)}"
        burn_di(di_list[1])
    end
end

def write_new_file()
    @new_file.each{|offset, value|
        @new_file_raw[offset] = value
    }
    open(@file+"_desobfu", "wb") {|io| io.write(@new_file_raw) }
end

@dasm.decoded.each{|addr, di|
    if not(defined?(di.block)) or di.block == nil or di.block.list[0].address != di.address
        next
    end
    
    c_block_dests = {}
    di.block.list.each{|cdi|
        # puts cdi
        # if a dereference of a traced register ?
        if (cdi.instruction.to_s.include?('[') and cdi.opcode.name != 'lea') or cdi.opcode.name =~ /(sto|movs)/
            get_regs_in_di(cdi).each{|creg|
                if c_block_dests[creg] != nil
                    if c_block_dests[creg].length > 1
                        puts "optimisable : #{c_block_dests[creg][0].to_s} / #{c_block_dests[creg][1].to_s}"
                        solve_optim(c_block_dests[creg])
                    end
                    c_block_dests[creg] = nil
                end
            }
        end
        
        # is optimisable instruction ?
        optim_reg = is_optim_instr(cdi)
        if optim_reg != nil
            if c_block_dests[optim_reg] == nil
               c_block_dests[optim_reg] = []
            end
            c_block_dests[optim_reg] << cdi
        end
        
        if cdi.opcode.name[0] == "j" and cdi.opcode.name != 'jmp'
            fl = @dasm.cpu.get_jump_condition(cdi)
            # puts cdi
            # pp @dasm.methods
            # exit()
            begin
                fresult = @dasm.backtrace(fl, cdi.address, :only_upto => true, :no_check => true)
            rescue
                puts "backtracing fail for #{cdi}"
                fresult = nil
            end
            if (fresult == [Expression[0]])
                puts "  [-] NOP predictive condition : #{cdi}"
                burn_di(cdi)
                log = []
                @dasm.backtrace(fl, cdi.address, :only_upto => true, :no_check => true,:log => log)
                log.each{|l_position,l_register,l_solve,l_di|
                    if l_di != nil
                        burn_di(l_di)
                    end
                }
            elsif (fresult == [Expression[1]])
                # @dasm.callback_prebacktrace = nil
                puts "  [-] JMP predictive condition : #{cdi}"
                # pp cdi.instruction.args[0]
                distance = @dasm.normalize(cdi.instruction.args[0]) - cdi.next_addr()
                if distance < 127 and distance > -127
                    replace_di(cdi, "db 0xeb, #{(distance&0xff)}")
                else
                    replace_di(cdi, cdi.instruction.to_s)
                end
                log = []
                @dasm.backtrace(fl, cdi.address, :only_upto => true, :no_check => true,:log => log)
                log.each{|l_position,l_register,l_solve,l_di|
                    if l_di != nil
                        burn_di(l_di)
                    end
                }
            end
        end
        if cdi.opcode.name == 'jmp'
            jdest = @dasm.normalize(cdi.instruction.args[0])
            if jdest.to_s =~ /^[0-9]+$/ and jdest > cdi.address
                di_list = []
                for i in 0..(jdest-cdi.next_addr()-1)
                    dest_di = @dasm.di_at(cdi.next_addr()+i)
                    if dest_di != nil
                        di_list << dest_di
                    end
                end
                if di_list.length == 0
                    puts "  [-] Erase dead code at #{cdi}"
                    replace_di(cdi, "db "+(["0x90"]*(jdest-cdi.address)).join(', '), true)
                end
            end
        end
    }
    c_block_dests.each{|creg, di_list|
        if di_list != nil
            if di_list.length > 1
                puts "  [?] Optimisable : #{di_list[0].to_s} / #{di_list[1].to_s}"
                solve_optim(di_list)
            end
            c_block_dests[creg] = nil
        end
    }
}

if @new_file != {}
    puts "[*] Write desobfuscated_file"
    write_new_file()
end
