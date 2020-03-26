# Solutions TP7
> Author(s): Guillaume Everarts de Velp  
> Last update: 26-03-2020

**Progress**
 - [x] [7.1 Environment Configuration](#71-environment-configuration)
 - [ ] [7.2 Evading Stack Protection](#71-format-string)

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

### Step by step :walking:

### Final solution :running:
