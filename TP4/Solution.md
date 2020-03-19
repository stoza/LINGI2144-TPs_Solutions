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
