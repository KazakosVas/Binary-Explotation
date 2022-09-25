# 1-byte buffer overflow

Our goal is to solve this explotation challenge <i> [Stack6](https://exploit.education/phoenix/stack-six/)</i>

A very interesting challenge because the overflow **only allows us to change the last byte of saved rbp.**

## Code to exploit
```

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *what = GREET;

char *greet(char *who) {
  char buffer[128];
  int maxSize;

  maxSize = strlen(who);
  if (maxSize > (sizeof(buffer) - /* ensure null termination */ 1)) {
    maxSize = sizeof(buffer) - 1;
  }

  strcpy(buffer, what);
  strncpy(buffer + strlen(buffer), who, maxSize);

  return strdup(buffer);
}

int main(int argc, char **argv) {
  char *ptr;
  printf("%s\n", BANNER);

#ifdef NEWARCH
  if (argv[1]) {
    what = argv[1];
  }
#endif

  ptr = getenv("ExploitEducation");
  if (NULL == ptr) {
    // This style of comparison prevents issues where you may accidentally
    // type if(ptr = NULL) {}..

    errx(1, "Please specify an environment variable called ExploitEducation");
  }

  printf("%s\n", greet(ptr));
  return 0;
}

```
## Problem of code
It is obvious that the problem of the code is found at 
```
strncpy(buffer + strlen(buffer), who, maxSize);
```
since this will overflow the buffer. We control the string (char *)who  because we control the environment variable ExploitEducation.

## Working with gdb

Check <i> [How gdb affects environment variables](https://stackoverflow.com/questions/50662903/differences-in-environment-layout-with-and-without-gdb
)</i>

Before running any command at gdb, run these
```
unset env LINES
unset env COLUMNS
set env _ /opt/phoenix/amd64/stack-six
```
We disassemble greet function and we will put a breakpoint before strncpy function so that we can
inspect the memory before and after strncpy



![](./images/phoenix2.2.png?)

**Memory before strncpy**. We overflow with A 

![](./images/bfrstrcpy.png?)

**Memory After strncpy**. We overflow with A

![](./images/afterstrcpywhit.png?)



We can only affect the last byte of saved rbp. Changing the saved rbp allows us to affect the return address of the function that called greet

Disassemble main

![](./images/mainwhite.png?)

Leave command <==> RSP = RBP + pop from stack.

So Saved_RBP+8 is the address main will return.




We find where our shellcode is in memory
![](./images/grepwhite.png?)
So our shellcode is found in memory address 0x7fffffffee2+strlen("ExploitEducation=) = 0x7fffffffef3

We will print memory of main before leave command
![](./images/mainbeforeleavewhite.png?)

We see that the address of our shellcode is placed in stack so we modify the last byte of Saved_rbp to be \x40

## Exploit Code
![](./images/realshellblck.png?)
Copy shellcode from
<i> [Shellcode](https://shell-storm.org/shellcode/files/shellcode-106.php)</i>


Final Root shell
![](./images/finalwhite.png?)


