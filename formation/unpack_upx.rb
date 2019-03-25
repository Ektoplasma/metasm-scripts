require 'metasm'
include Metasm
require 'pp'

file = ARGV.shift

def find_iat(pe)		
    @iat_bp = 0
    dasm = pe.disassemble_fast_deep 'entrypoint'
    dasm.sections.each{ |s|
        r = Regexp.new("\x89\x03\x83\xc3\x04".force_encoding("binary"), Regexp::FIXEDENCODING)
        if s[1].data.index(r) != nil
            @iat_bp = dasm.normalize(s[0]+s[1].data.index(r))
        end
    }
    raise "No UPX constant found :-(" if @iat_bp == 0
    nil
end	

def find_oep(pe)		
    dasm = pe.disassemble_fast_deep 'entrypoint'
    
    return if not jmp = dasm.decoded.find { |addr, di|
        next if not di.block_head?
        b = di.block
        next if b.to_subfuncret.to_a.length != 0 or b.to_normal.to_a.length != 1
        to = b.to_normal.first
        next if not s = dasm.get_section_at(to)
        next if dasm.get_section_at(di.address) == s

        true
    }
    dasm.normalize(jmp[1].block.to_normal.first)
end	

def debugloop
    @iat = 0xffffffff
    @dbg.bpx(@iat_bp, false) { buildIAT_callback }
    @dbg.hwbp(@oep, :x, 1, true) { breakpoint_callback }
    @dbg.run_forever
    puts 'done'
end

def buildIAT_callback
    if @dbg.ctx[:ebx] < (@iat + @dbg.os_process.modules[0].addr)
        @iat = @dbg.ctx[:ebx] - @dbg.os_process.modules[0].addr
        puts "  IAT address set at 0x#{@iat.to_s(16)}"
    end
end

def breakpoint_callback
    puts 'breakpoint hit !'

    puts "@baseaddr = #{@baseaddr.to_s(16)}"
    dump = LoadedPE.memdump @dbg.memory, @baseaddr, @oep, @iat

    dump.sections.each { |s| s.characteristics |= ['MEM_WRITE'] }
    dump.optheader.dll_characts = 0
    dump.optheader.subsystem = @ori_pe.optheader.subsystem

    dump.encode_file @dumpfile

    puts 'dump complete'
ensure
    @dbg.kill
end


@dumpfile = file.chomp('.exe') + '.dump.exe'

puts '##############################################'
puts '####  Unpacking UPX loader'
puts '##############################################'
pe = PE.decode_file(file)
@ori_pe = pe
@baseaddr = pe.optheader.image_base

@oep = find_oep(pe)
raise 'cant find oep...' if not @oep
puts "oep found at #{Expression[@oep]}"

find_iat(pe)

@pr = OS.current.create_process(file)
@dbg = @pr.debugger
puts 'running...'
debugloop
