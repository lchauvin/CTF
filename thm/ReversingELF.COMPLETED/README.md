# ReversingELF

Laurent Chauvin | April 07, 2024

## Resources

[1] https://gchq.github.io/CyberChef
[2] https://xor.pw/
[3] https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html

## Progress

#### Task 1 : Crackme1

We just need to download the file, make it executable `chmod +x crackme1`, and run it: `flag{not_that_kind_of_elf}`

#### Task 2 : Crackme2

The second one require a password:

```bash
./crackme2

Usage: ./crackme2 password
```

Let's check strings:

```bash
...
Usage: %s password
super_secret_password
Access denied.
Access granted.
...
```

Let's try `super_secret_password`:

```bash
./crackme2 super_secret_password

Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
```

#### Task 3 : Crackme3

The third one also needs a password

```bash
./crackme3                

Usage: ./crackme3 PASSWORD
```

Let's check strings again:

```bash
...
Usage: %s PASSWORD
malloc failed
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
Correct password!
Come on, even my aunt Mildred got this one!
...
```

This looks like a base64 string. Let's decode it using [1]: `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`.


#### Task 4 : Crackme4

When running we get:

```bash
Usage : ./crackme4 password

This time the string is hidden and we used strcmp
```

We can see in the strings:

```bash
...
get_pwd
_ITM_deregisterTMCloneTable
data_start
puts@@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@@GLIBC_2.4
printf@@GLIBC_2.2.5
compare_pwd
...
```

Let's bypass the comparison. After inspecting code with Ghidra, I realized we won't be able to bypass the comparison, as the password is the flag we need, so we need to find it (bypassing the comparison would just tell us we have the right password all the time, but it won't help us get the flag).

After spending few hours getting familiar with Ghidra, I analyzed the code, and focused on the function `get_pwd` and `compare_pwd`.

`compare_pwd` looks like this:

```c
void compare_pwd(char *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  undefined2 local_18;
  undefined local_16;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x7b175614497b5d49;
  local_20 = 0x547b175651474157;
  local_18 = 0x4053;
  local_16 = 0;
  get_pwd((long)&local_28);
  iVar1 = strcmp((char *)&local_28,param_1);
  if (iVar1 == 0) {
    puts("password OK");
  }
  else {
    printf("password \"%s\" not OK\n",param_1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see some local variables (`local_28`, `local_20`, `local_18` and `local_16`). Then `get_pwd` is called on `local_28`, then `local_28` is compared to the entered password.

I initially thought that `local_28` was an address, before I realized it was a value.

Let's check what `get_pwd` is doing:

```c
void get_pwd(long param_1)

{
  int local_c;
  
  local_c = -1;
  while (local_c = local_c + 1, *(char *)(param_1 + local_c) != '\0') {
    *(byte *)(local_c + param_1) = *(byte *)(param_1 + local_c) ^ 0x24;
  }
  return;
}
```

It's basically a loop, that will `xor` each byte by `0x24` in place, until it finds a `null` character (`\0`).

Let's go back to those local variables. Only the address of `local_28` is given to the function, so I initially tried to `xor` value of `local_28` with `0x24`, but no success.

Then, I realized the `get_pwd` only stops when it finds a `null` character, so after reading all bytes on `local_28` it will continue to read what's on the stack, and as `local_20`, `local_18` and `local_16` are allocated right after, they should be on the stack too. So it will `xor` all those values until reaching `local_16` (`\0`).

I started to calculate `xor` bytes by bytes using [2], but I remembered that values are store from left to right, so `0x7b175614497b5d49` would actually results in bytes in this order `49 5d 7b 49 14 56 17 7b`.

In the end the sequence is: `49 5d 7b 49 14 56 17 7b 57 41 47 51 56 17 7b 54 53 40`, when `xor` with `0x24` gives `6d 79 5f 6d 30 72 33 5f 73 65 63 75 72 33 5f 70 77 64`, when converting back to ASCII with [3] gives: `my_m0r3_secur3_pwd`.

Let's verify:

```bash
./crackme4 my_m0r3_secur3_pwd

password OK
```

#### Task 5 : Crackme5

Let's run it:

```bash
./crackme5                    

Enter your input:
test
Always dig deeper
```

Let's open it in Ghidra. Here is the main function:

```c

undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 'O';
  local_37 = 0x66;
  local_36 = 100;
  local_35 = 0x6c;
  local_34 = 0x44;
  local_33 = 0x53;
  local_32 = 0x41;
  local_31 = 0x7c;
  local_30 = 0x33;
  local_2f = 0x74;
  local_2e = 0x58;
  local_2d = 0x62;
  local_2c = 0x33;
  local_2b = 0x32;
  local_2a = 0x7e;
  local_29 = 0x58;
  local_28 = 0x33;
  local_27 = 0x74;
  local_26 = 0x58;
  local_25 = 0x40;
  local_24 = 0x73;
  local_23 = 0x58;
  local_22 = 0x60;
  local_21 = 0x34;
  local_20 = 0x74;
  local_1f = 0x58;
  local_1e = 0x74;
  local_1d = 0x7a;
  puts("Enter your input:");
  __isoc99_scanf(&DAT_00400966,local_58);
  iVar1 = strcmp_(local_58,&local_38);
  if (iVar1 == 0) {
    puts("Good game");
  }
  else {
    puts("Always dig deeper");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can see it looks a bit similar to the previous crack.

By converting all values from hex (except for `local_38` and `local_36`) to ASCII with [3], we get 

```
OfdlDSA|3tXb32~X3tX@sX`4tXtz
```

`local_38` and `local_36` are respectively a char ('O') with hex value `0x4f` and a decimal value (100) with an hex value of `0x64`. This can also be seen in the listing window of Ghidra:

```
        00400791 c6 45 d0 4f     MOV        byte ptr [RBP + local_38],0x4f
        00400795 c6 45 d1 66     MOV        byte ptr [RBP + local_37],0x66
        00400799 c6 45 d2 64     MOV        byte ptr [RBP + local_36],0x64
        0040079d c6 45 d3 6c     MOV        byte ptr [RBP + local_35],0x6c
        004007a1 c6 45 d4 44     MOV        byte ptr [RBP + local_34],0x44
        004007a5 c6 45 d5 53     MOV        byte ptr [RBP + local_33],0x53
        004007a9 c6 45 d6 41     MOV        byte ptr [RBP + local_32],0x41
        004007ad c6 45 d7 7c     MOV        byte ptr [RBP + local_31],0x7c
        004007b1 c6 45 d8 33     MOV        byte ptr [RBP + local_30],0x33
        004007b5 c6 45 d9 74     MOV        byte ptr [RBP + local_2f],0x74
        004007b9 c6 45 da 58     MOV        byte ptr [RBP + local_2e],0x58
        004007bd c6 45 db 62     MOV        byte ptr [RBP + local_2d],0x62
        004007c1 c6 45 dc 33     MOV        byte ptr [RBP + local_2c],0x33
        004007c5 c6 45 dd 32     MOV        byte ptr [RBP + local_2b],0x32
        004007c9 c6 45 de 7e     MOV        byte ptr [RBP + local_2a],0x7e
        004007cd c6 45 df 58     MOV        byte ptr [RBP + local_29],0x58
        004007d1 c6 45 e0 33     MOV        byte ptr [RBP + local_28],0x33
        004007d5 c6 45 e1 74     MOV        byte ptr [RBP + local_27],0x74
        004007d9 c6 45 e2 58     MOV        byte ptr [RBP + local_26],0x58
        004007dd c6 45 e3 40     MOV        byte ptr [RBP + local_25],0x40
        004007e1 c6 45 e4 73     MOV        byte ptr [RBP + local_24],0x73
        004007e5 c6 45 e5 58     MOV        byte ptr [RBP + local_23],0x58
        004007e9 c6 45 e6 60     MOV        byte ptr [RBP + local_22],0x60
        004007ed c6 45 e7 34     MOV        byte ptr [RBP + local_21],0x34
        004007f1 c6 45 e8 74     MOV        byte ptr [RBP + local_20],0x74
        004007f5 c6 45 e9 58     MOV        byte ptr [RBP + local_1f],0x58
        004007f9 c6 45 ea 74     MOV        byte ptr [RBP + local_1e],0x74
        004007fd c6 45 eb 7a     MOV        byte ptr [RBP + local_1d],0x7a
```

#### Task 6 : Crackme6

Let's open it with Ghidra.

Here is the main function:

```c
undefined8 main(int param_1,undefined8 *param_2)

{
  if (param_1 == 2) {
    compare_pwd((char *)param_2[1]);
  }
  else {
    printf("Usage : %s password\nGood luck, read the source\n",*param_2);
  }
  return 0;
}
```

To make things a bit clearer, let's left click on the definition of the main function and `Edit Function Signature`, then enter the following definition `int main (int argc, char **argv)`, then we have

```c
int main(int argc,char **argv)

{
  if (argc == 2) {
    compare_pwd(argv[1]);
  }
  else {
    printf("Usage : %s password\nGood luck, read the source\n",*argv);
  }
  return 0;
}
```

Let's check `compare_pwd`:

```c
void compare_pwd(char *param_1)

{
  undefined8 uVar1;
  
  uVar1 = my_secure_test(param_1);
  if ((int)uVar1 == 0) {
    puts("password OK");
  }
  else {
    printf("password \"%s\" not OK\n",param_1);
  }
  return;
}
```

Let's check `my_secure_test`:

```c
undefined8 my_secure_test(char *param_1)

{
  undefined8 uVar1;
  
  if ((*param_1 == '\0') || (*param_1 != '1')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[1] == '\0') || (param_1[1] != '3')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[2] == '\0') || (param_1[2] != '3')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[3] == '\0') || (param_1[3] != '7')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[4] == '\0') || (param_1[4] != '_')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[5] == '\0') || (param_1[5] != 'p')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[6] == '\0') || (param_1[6] != 'w')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[7] == '\0') || (param_1[7] != 'd')) {
    uVar1 = 0xffffffff;
  }
  else if (param_1[8] == '\0') {
    uVar1 = 0;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
```

Damn that's some ugly code !! Anyway, we can see `1337_pwd`. 

Let's verify:

```bash
./crackme6 1337_pwd

password OK
```

#### Task 7 : Crackme7

Let's have a look at the program first:

```bash
./crackme7

Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 1
What is your name? you
Hello, you!
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 2
Enter first number: 1234
Enter second number: 2
1234 + 2 = 1236
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 0
Unknown choice: 0

```

No password in sight. It also seems it's checking for wrong choices.

Anyway, let's open it with Ghidra:

```c
undefined4 main(undefined param_1)

{
  int iVar1;
  undefined4 *puVar2;
  byte bVar3;
  undefined4 local_80 [25];
  int local_1c;
  int local_18;
  int local_14;
  undefined *local_10;
  
  bVar3 = 0;
  local_10 = &param_1;
  while( true ) {
    while( true ) {
      puts("Menu:\n\n[1] Say hello\n[2] Add numbers\n[3] Quit");
      printf("\n[>] ");
      iVar1 = __isoc99_scanf(&DAT_08048814,&local_14);
      if (iVar1 != 1) {
        puts("Unknown input!");
        return 1;
      }
      if (local_14 != 1) break;
      printf("What is your name? ");
      puVar2 = local_80;
      for (iVar1 = 0x19; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar2 = 0;
        puVar2 = puVar2 + (uint)bVar3 * -2 + 1;
      }
      iVar1 = __isoc99_scanf(&DAT_0804883a,local_80);
      if (iVar1 != 1) {
        puts("Unable to read name!");
        return 1;
      }
      printf("Hello, %s!\n",local_80);
    }
    if (local_14 != 2) {
      if (local_14 == 3) {
        puts("Goodbye!");
      }
      else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
      }
      else {
        printf("Unknown choice: %d\n",local_14);
      }
      return 0;
    }
    printf("Enter first number: ");
    iVar1 = __isoc99_scanf(&DAT_08048875,&local_18);
    if (iVar1 != 1) break;
    printf("Enter second number: ");
    iVar1 = __isoc99_scanf(&DAT_08048875,&local_1c);
    if (iVar1 != 1) {
      puts("Unable to read number!");
      return 1;
    }
    printf("%d + %d = %d\n",local_18,local_1c,local_18 + local_1c);
  }
  puts("Unable to read number!");
  return 1;
}
```

We notice this snippet:

```c
      else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
      }
```

where `local_14` seems to be the menu choice. We could either look at the `giveFlag` function, but it looks annoying to figure it out:

```c
void giveFlag(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  char local_ca [34];
  undefined4 local_a8 [34];
  uint local_20;
  
  puVar2 = &DAT_080488e0;
  puVar3 = local_a8;
  for (iVar1 = 0x22; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  memset(local_ca,0x41,0x22);
  for (local_20 = 0; local_20 < 0x22; local_20 = local_20 + 1) {
    local_ca[local_20] = (char)local_a8[local_20] + local_ca[local_20];
  }
  puts(local_ca);
  return;
}
```

Instead, let's find the path that would give us the flag: first we need the choice to be different from 2 to get in here:

```c
   if (local_14 != 2) {
      if (local_14 == 3) {
        puts("Goodbye!");
      }
      else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
      }
      else {
        printf("Unknown choice: %d\n",local_14);
      }
      return 0;
    }
```

Then we need the choice to be equal to `0x7a69` with is `31337` in decimal.

Let's verify:

```bash
/crackme7

Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 31337
Wow such h4x0r!
flag{much_reversing_very_ida_wow}
```

#### Task 8 : Crackme8

Let's try to run it:

```bash
./crackme8 test

Access denied.
```

Fine, let's open Ghidra. Let's redefine the main signature as seen before, and we have:

```c
int main(int argc,char **argv)

{
  int iVar1;
  
  if (argc == 2) {
    iVar1 = atoi(argv[1]);
    if (iVar1 == -0x35010ff3) {
      puts("Access granted.");
      giveFlag();
      iVar1 = 0;
    }
    else {
      puts("Access denied.");
      iVar1 = 1;
    }
  }
  else {
    printf("Usage: %s password\n",*argv);
    iVar1 = 1;
  }
  return iVar1;
}
```

Again, we could look at `giveFlag` function, but it looks annoying:

```c

void giveFlag(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  char local_14c [60];
  undefined4 local_110 [60];
  uint local_20;
  
  puVar2 = &DAT_080486a0;
  puVar3 = local_110;
  for (iVar1 = 0x3c; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  memset(local_14c,0x41,0x3c);
  for (local_20 = 0; local_20 < 0x3c; local_20 = local_20 + 1) {
    local_14c[local_20] = (char)local_110[local_20] + local_14c[local_20];
  }
  puts(local_14c);
  return;
}
```

Let's find the right path instead. We can see it converts our entered password to int, using `atoi`, then compare to `-0x35010ff3` to grant us the access. Let's convert this to decimal: `-889262067`, and verify it works:

```bash
./crackme8 -889262067

Access granted.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```

## Flag

1. `flag{not_that_kind_of_elf}`

2. `flag{if_i_submit_this_flag_then_i_will_get_points}`

3. `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`

4. `my_m0r3_secur3_pwd`

5. `OfdlDSA|3tXb32~X3tX@sX``4tXtz` (quote escaped)

6. `1337_pwd`

7. `flag{much_reversing_very_ida_wow}`

8. `flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`
