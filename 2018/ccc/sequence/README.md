# Sequence @ 35C3CTF

I wish to start with an apology: this one is by far my worst CTF solution. To this moment - I have no idea what was the bug exactly. Our exploit worked statistically. We mostly guess-worked our way. And if you asked me to do it again from scratch, it would probably take the same amount of time.

However, we first-blooded it and only 3 teams in total solved it, so I feel it's worth sharing. But don't expect some sudden clarity moments or non-vague explanations. You will only be disappointed. All I can offer is a wild hand waving and some intelligent guesses.

## Challenge
In the [tarball](sequence-afcf267d78429b4a36dca5bd12bdf45e.tar.gz) you get a Ruby interpreter, libc binary and file named `challenge.rb` which contains the challenge and some other files that are needed to set up the Docker for this challenge (proof of work script, Dockerfile). There is also a README which explains how this whole thing was set up - it's a relatively recent version of Ruby and recent glibc version that run in Ubuntu 18.10 and execute the `challenge.rb` file. The README also hints that https://github.com/niklasb/rubyfun may be helpful.

Here is the challenge server:
```ruby
strs = {}

loop do
  print '> '
  STDOUT.flush
  cmd, *args = gets.split
  begin
    case cmd
    when 'disas'
      stridx = args[0].to_i
      puts RubyVM::InstructionSequence::load_from_binary(strs[stridx]).disasm
    when 'gc'
      GC.start
    when 'write'
      stridx, i, c = args.map(&:to_i)
      (strs[stridx] ||= "\0"*(i + 1))[i] = c.chr
    when 'delete'
      stridx = args[0].to_i
      strs.delete stridx
    else
      puts "Unknown command"
    end
    STDOUT.flush
  rescue => e
    puts "Error: #{e}"
  end
end
```
It's quite simple. The server has some dictionary of strings which the client can add or delete strings with integers as indices. Adding a string is done by sending a `write <idx> <offset> <char>` message, so we can write with an offset. The client can also manually invoke the garbage collector. So far nothing interesting. But there is also a `disas` command which disassembles a string with the `RubyVM::InstructionSequence::load_from_binary` API and prints it to the user. That's it. Adding strings, deleting strings, disassembling strings as ruby instructions and invoking the garbage collector.

`RubyVM::InstructionSequence` is the way the Ruby VM represents compiled instructions before interpretation. They have their own file format and you can find it's "documentation" in the code.

## Bugs
We initially thought it might be a recently fixed bug in Ruby that was not included in the compiled version, but reading the commit logs after the version we received yielded nothing.
We decided to check that rubyfun repo and saw it differs in one commit only from vanila Ruby - it adds an LLVM based fuzzer. This fuzzer targets specifically the RubyVM::InstructionSequence::load_from_binary API and the GC. Seems rather interesting. So we built the fuzzer according to the instructions and gave it a spin. It instantaneously started to spit out crashes. Cheers!
So we ought to exploit an 0day in Ruby, how nice :)

## Memory Leak
We executed one of the crashing samples under a debugger and found which part of the code is responsible for parsing this weird file format. We started reading it and tried to build our own file conforming to it from scratch. It uses many offsets in many places but never checks these offsets are not out of bound. So it is quite easy to relatively point to data in the process memory. Perfect for a leak.
However, building this format from scratch is a tedious work which we gave up on after a few hours. My team mate had a better idea - compile a Ruby file that all it has is a string and then change the size of that string in the compiled file. In the fuzzer repo there is a script to compile Ruby code.
This worked exactly as expected! We binary edited the compiled file - increased the string size - and sent it to the server. It printed back plenty of binary data that turned out to be data from the heap. We searched and found some pointers there that turned out to point to the heap and libc. Exactly what we needed.

## UAF
We continued reading the implementation, but it was getting overly complicated. We realized that pointing outside our data is good for reading memory, but for getting code execution we need something else. Parsing wrong data is not a promising way to go.
So we turned back to the fuzzer and read the summaries of the logs. Most of them were simple segfaults on reads. But a few had this note:
> == 15659==ERROR: AddressSanitizer: attempting to call malloc_usable_size() for pointer which is not owned: 0x000000000300

Which seemed interesting. It means for some reason something that is obviously not a pointer is considered a pointer to a chunk. We executed this under a debugger and so it crashed during garbage collection when destroying the `iseq` object that suppose to hold the compiled instructions.
It was even better, it was calling `ruby_xfree` on that pointer when it crashed. Which means that if the pointer was pointing to some valid memory, that memory would have been `free`d.
The pointer was `body->param.opt_table` in the `rb_iseq_free` function.

We stared at the crashing sample for a while and found the "pointer" that was passed to `ruby_xfree` was actually written there. We flipped bits to verify it - and we were right - it is read from the string which is decompiled. We have no idea why.

Given the info leak, we have all that we need to pass `free` a pointer to our data.

After we survived the first crash, it turned out there are two more places where malformed pointer is passed to free, using the `body->param.keyword` in the same function. Fortunately those two other places are also copied from our supplied input so we simply made them NULL.

## Exploitation
After sending the leaking string, we changed it and made it look like a 0x70 size memory chunk. We then crafted the UAF string to point to this chunk and triggered the UAF. This gave us control of a freed chunk in the 0x70 fastbin. Then we used fastbin attack to overwrite `__realloc_hook` with a pointer to `system`.
Finally we wrote a string `/bin/sh\x00` and started to increase it's size, adding data to the end. At some point `realloc` was invoked with our data as input which made it execute a shell. The end.
