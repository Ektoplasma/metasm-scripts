require 'metasm'
include Metasm
require 'pp'

file = ARGV.shift

def hook_CreateThread()
    puts "Hey !"
end

puts '##############################################'
puts '####  Unpacking RedOctober'
puts '##############################################'
pe = PE.decode_file(file)
@ori_pe = pe
@baseaddr = pe.optheader.image_base

def start_32b()
    createThread_addr = GetAddress("kernelbase.dll","CreateThread")
    if virtualAlloc_addr != 0
        @dbg.callback_exception = nil
        @dbg.bpx(createThread_addr, false) { hook_CreateThread() }
    end
    @dbg.pass_current_exception
end

@pr = OS.current.create_process(file)
@dbg = @pr.debugger
puts 'running...'
@dbg.callback_exception = lambda{ |e| start_32b()}
@dbg.run_forever
