# Solutions TP 4

## 4.2
This is exactly the code given in the slides. The critical part is the following:
```c
int auth_flag = 0;
char password_buffer[16];
strcpy(password_buffer,password);
```

So we see we have a buffer of length 16 and just "above" a variable which given us access to a critical section.
We can do 3 differents things:
1. put a password of length < 16: unless we found the right password, this will give us a "bad password!".
2. put a password of length > 16 && length < 25: this will give us a "bad password!" but as we have rewrite the auth_flag this will also give us a "access granted"
3. put a password of length > 25 this will give us "bad password!" and then "seg fault" as we've gone to far and also rewrite the saved eip

## 4.3
Here we have the same code as 4.2 but with a stack protector. So if we try a password longer than 16 we get a "stack smashed detected aborted"
If we compare the 2 different code in gdb and more specially the **check_authentification** we can see the difference between the 2 code. 
[difference between 4.2 and 4.3](img/diff_43-42.png)

We can see on the picture above, that the right code (which is the one with the protection) is bigger than the left code. 
Then we notice on the right code at address **0X000011e1** that we put something on eax. This something is a random value generated from a gs register.
Then this random value will be put on the stack and this will become the protection also known as canari(see following lectures).
