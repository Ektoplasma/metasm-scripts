require 'metasm'
include Metasm
require 'pp'

def find_iat(pe)		
    @iat_bp = 0
    r = Regexp.new("\x89\x03\x83\xc3\x04".force_encoding("binary"), Regexp::FIXEDENCODING)
    if (@pr.memory[@dbg.ctx[:eip],0x300].index(r)) == nil
        raise "No UPX IAT found :-("
    end
    @iat_bp = (@pr.memory[@dbg.ctx[:eip],0x300].index(r)  + @dbg.ctx[:eip])
    # puts "IAT bp -> #{@iat_bp}"
    nil
end	

def find_1erStep()
    # puts "find_1erStep called"
    @find_1erStep_addr = 0
    r = Regexp.new("\x33\xc9\x64......\x8b..\x8b..\x8b".force_encoding("binary"), Regexp::FIXEDENCODING)
    if @pr.memory[(@dbg.modules[0].addr),@dbg.modules[0].size].index(r) != nil
        @find_1erStep_addr = @pr.memory[(@dbg.modules[0].addr),@dbg.modules[0].size].index(r)  + @dbg.modules[0].addr
        puts "  [*] 1st step is at #{@find_1erStep_addr.to_s(16)}"
    end
    raise "No RedOctober constant found :-(" if @find_1erStep_addr == 0
    nil
end	

def hook_6()
    puts "    [*] Parsing UPX layer"
    # pp @pr.memory[GetAddress("kernel32.dll","VirtualAlloc"), 5] 
    # @dbg.bpx(GetAddress("kernel32.dll","VirtualAlloc"), true) { hook_4 }
    @cdasm = @dbg.disassembler
    @oep = find_oep(@cdasm)
    # pp @oep
    raise 'cant find oep...' if not @oep
    puts "    [*] OEP found at #{Expression[@oep]}" if @oep
    if @oep == @dbg.ctx[:eip]
        @iat = nil
        breakpoint_callback()
    end
    find_iat(@cdasm)
    raise 'cant find iat...' if @iat_bp == 0
    @dbg.bpx(@iat_bp, false) { buildIAT_callback }
    @dbg.hwbp(@oep, :x, 1, true) { breakpoint_callback }
    # puts "Go !!"
    @dbg.run_forever
    puts 'done'
    # sleep 99999
end	

def hook_5()
    puts "    [*] RedOctober packer layers down"
    # pp @pr.memory[GetAddress("kernel32.dll","VirtualAlloc"), 5] 
    # @dbg.bpx(GetAddress("kernel32.dll","VirtualAlloc"), true) { hook_4 }
    @dbg.bpx(@dbg.ctx[:ebx], true) { hook_6 }
    # sleep 99999
end	

def hook_4()
    puts "    [*] VirtualAlloc called"
    # pp @pr.memory[GetAddress("kernel32.dll","VirtualAlloc"), 5] 
    # @dbg.bpx(GetAddress("kernel32.dll","VirtualAlloc"), true) { hook_4 }
    r = Regexp.new("\xff\xe3\xc9\xc2\x08\x00".force_encoding("binary"), Regexp::FIXEDENCODING)
    @upx_point = 0
    if (@pr.memory[@dbg.memory_read_int(@dbg.ctx[:esp]),0x300].index(r)) == nil
        puts "No jmp ebx found :-("
    end
    @upx_point = @pr.memory[@dbg.memory_read_int(@dbg.ctx[:esp]),0x300].index(r)  + @dbg.memory_read_int(@dbg.ctx[:esp])
    puts "  [*] jmp ebx is at #{@upx_point.to_s(16)}"
    @dbg.bpx(@upx_point, true) { hook_5 }
    # sleep 99999
end	

def hook_3()
    puts "    [*] UnmapViewOfFile called"
    # pp @pr.memory[GetAddress("kernel32.dll","VirtualAlloc"), 5] 
    @dbg.bpx(GetAddress("kernel32.dll","VirtualAlloc"), true) { hook_4 }
    # sleep 99999
end	

def hook_2ndStep()
    puts "    [*] VirtualAlloc called"
    # pp @pr.memory[GetAddress("kernel32.dll","VirtualAlloc"), 5] 
    @dbg.bpx(GetAddress("kernel32.dll","UnmapViewOfFile"), true) { hook_3 }
    # sleep 99999
end

def hook_1erStep()
    puts "    [*] 1st step of unpacking"
    @dbg.bpx(GetAddress("kernel32.dll","VirtualAlloc"), true) { hook_2ndStep }
    
end	

# disassemble the upx stub to find a cross-section jump (to the real entrypoint)
def find_oep(pe)		
    @cdasm.disassemble_fast_deep @dbg.ctx[:eip]
    
    r = Regexp.new("\x89\x03\x83\xc3\x04".force_encoding("binary"), Regexp::FIXEDENCODING)
    @upx_point = 0
    if (@pr.memory[@dbg.ctx[:eip],0x300].index(r)) == nil
        puts "No UPX"
        return @dbg.ctx[:eip]
    end
    upx_ret = (@pr.memory[@dbg.ctx[:eip],0x300].index(r)  + @dbg.ctx[:eip])+9
    di = @cdasm.di_at(upx_ret)
    puts "    [*] UPX jmp is to #{@cdasm.normalize(di.block.to_normal.first).to_s(16)}"

    # now jmp is a couple [addr, di], we extract and normalize the oep from there
    @cdasm.normalize(di.block.to_normal.first)
end	

def hookApiSetPriorityClass
    # puts "HookAPI"
    
    if @dbg.modules.length > 0
        # pp @dbg.loadallsyms
        
        pe_tmp = LoadedPE.load @pr.memory[@pr.modules[0].addr, 0x1000000]
        pe_tmp.decode_header
        pe_tmp.decode_imports
        iat_entry_len = pe_tmp.encode_xword(0).length	# 64bits portable ! (shellcode probably won't work)
        pe_tmp.imports.each { |id|
            id.imports.each_with_index { |i, idx|
                case i.name
                when 'SetPriorityClass'
                    @setpriorityclass_p = @pr.modules[0].addr + id.iat_p + iat_entry_len * idx
                    # pp @dbg.ctx[:eip].to_s(16)
                    # Metasm::Gui::DbgWindow.new(@dbg, "#{@pr.pid} - metasm debugger")
                     # Gui.main
                    @setpriorityclass = @dbg.memory_read_int(@setpriorityclass_p)
                end
            }
        }
        
    end
    if @setpriorityclass_p > 0
        @pr.memory[@setpriorityclass, 3] = "\xc2\x08\x00" # patch SetPriorityClass to do nothing. If you don't do it priority of your process will be very low
        puts '  [*] SetPriorityClass patched'
    end
    find_1erStep()
    if @find_1erStep_addr > 0
        @dbg.bpx(@find_1erStep_addr, false) { hook_1erStep }
    end
    
end

def showGui
    Metasm::Gui::DbgWindow.new(@dbg, "#{@pr.pid} - metasm debugger")
    Gui.main
end

def debugloop
    # set up a oneshot breakpoint on oep
    @iat = 0xffffffff
    @setpriorityclass_p = 0
    # puts "Set a hook at 0x#{(@ori_pe.optheader.entrypoint + @baseaddr).to_s(16)}"
    @dbg.bpx(@ori_pe.optheader.entrypoint + @baseaddr, true) { hookApiSetPriorityClass }
    # Disable IsDebuggerPresent flag
    sc = Shellcode.assemble(Ia32.new, <<EOS)
pushad
mov eax, fs:[0x00000018]
mov eax, [eax+0x30]
mov byte ptr [eax+0x2], 0
popad
jmp entrypoint
ret
EOS
    sc.encoded.fixup! 'entrypoint' => @dbg.ip 
    
    injected = WinAPI.virtualallocex(@pr.handle, 0, sc.encoded.length, WinAPI::MEM_COMMIT|WinAPI::MEM_RESERVE, WinAPI::PAGE_EXECUTE_READWRITE)
    
    puts "  [*] Shellcode injected at 0x#{injected.to_s(16)}"
    
    sc.base_addr = injected
    raw = sc.encode_string
    @pr.memory[injected, raw.length] = raw
    @dbg.ip = injected
    
    @dbg.run_forever
    puts 'done'
    
	
end

def buildIAT_callback
    if @dbg.ctx[:ebx] < (@iat + @dbg.os_process.modules[0].addr)
        @iat = @dbg.ctx[:ebx] - @dbg.os_process.modules[0].addr
        puts "    [*] IAT address set at 0x#{@iat.to_s(16)}"
    end
end

def breakpoint_callback
    puts '  [*] Dumping Unpacked process'

    puts "@baseaddr = #{@baseaddr.to_s(16)}"
    dump = LoadedPE.memdump @dbg.memory, @baseaddr, @oep, @iat

    dump.sections.each { |s| s.characteristics |= ['MEM_WRITE'] }
    dump.optheader.dll_characts = 0
    dump.optheader.subsystem = @ori_pe.optheader.subsystem

    dump.encode_file @dumpfile

    puts 'dump complete'
    @dbg.kill
    exit
end

def GetAddress(modulename, funcname)
    results = []
    @dbg.symbols.each{|m|
        if m[1].casecmp(funcname) == 0
            results << m
        end
    }
    @dbg.modulemap.each{|module_name, module_addr|
        if module_name.casecmp(modulename) == 0
            results.each{|addr, name|
                if addr >= module_addr[0] and addr <= module_addr[1]
                    puts "    [*] #{funcname} is at 0x#{addr.to_s(16)}" if @verbose == true
                    return addr
                end
            }
        end
    }
    0
end

def isInModules(addr)
    @dbg.modulemap.each{|module_name, module_addr|
        if addr >= module_addr[0] and addr <= module_addr[1]
            return true
        end
    }
    return false
end

def isInPE(addr)
    if addr >= @dbg.os_process.modules[0].addr and addr <= (@dbg.os_process.modules[0].addr+@dbg.os_process.modules[0].size)
        return true
    end
    return false
end

file = ARGV.shift

@dumpfile = file.chomp('.exe') + '.dump._bad_exe'

puts '##############################################'
puts '####  Unpacking RedOctober packer'
puts '##############################################'
pe = PE.decode_file(file)
@ori_pe = pe
@baseaddr = pe.optheader.image_base

entrypoints = []
entrypoints << 'entrypoint'
@dasm = pe.disassemble_fast_deep 'entrypoint'
@pr = OS.current.create_process(file)
@dbg = @pr.debugger

puts 'running...'
debugloop
