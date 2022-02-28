# simple_linux_inmemory_debugger
This is a simple program that will attack a program "already running"( process ) in memory through the PTRACE linux system call.

_Capable of modifying the victim program registers' data_

**Simple reminder: a program in execution is a PROCESS.**

# HOW IT WORKS
- It will attach itself to a given process through the PID( Process Identifier ) you provide at the command line.

- It will save the victim program's previous state( registers ) before overwriting it with whatever shellcode you provide it with
( I attached a simple x86_64 assembly code with its shellcode to prove it works but it can work for any shellcode as long as the victim program supports its size ).

- After that it'll overwrite the registers( RIP in particular ) with your shellcode.

- The victim program will be continued by the debugger thus running your shellcode( You have pwned the program!! ).

- Once the shellcode is through with it's destruction, the debugger will replace the victim program's previous state for the current state( neat, right! all footprints were left in memory ) hence bringing back the 
victim program to it's own life!

# Compilation
Please make sure to have "gcc" and "make" installed( _Installed by default on most GNU/Linux systems_ ).
      
      make

# USAGE
WOW! it's very SIMPLE!

    root@hacker:~# ./process_attacker <PID>

# NOTE
- Make sure you are **ROOT!**
- Assembly( x86_64 or 64-bit ) was written in Intel syntax with the goal of using it with the [nasm](https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/) assembler.

- There many sites on the internet that can teach you on how to extract shellcode from your target programs( they're many ways trust me ). To do this manually, try reading from this gorgeous [site](http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/shellcode-walkthrough#getting-a-binary-and-byte-string-shellcode) . But if you hate that stress, try my own [tool](https://github.com/winterrdog/shellcode-myner) or [Neetx's tool](https://github.com/Neetx/Shellcode-Extractor)

- Only works on **GNU/Linux** systems. I haven't yet tried to port it to MAC OSX( But you can try it out :) ). 
