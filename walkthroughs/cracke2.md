# Reversing ELF

This is a writeup of the `crackme2` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: fb76894b44e6ce51c0a0fefd977a80c0

## Solution

### Dynamic Solution

This is a very simple crackme. Upon making the binary executable and running it, it tells us the usage:

```sh
$ ./crackme2 
Usage: ./crackme2 password
```

To find the password, we open it in `rizin`. After printing the usage message, a string is compared to another one using `strcmp`:

```asm
0x080484db      push  str.super_secret_password            ; 0x8048674 ; "super_secret_password" ; const char *s2
0x080484e0      push  eax                                  ; const char *s1
0x080484e1      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
```

From the comment in rizin, we can see that the password is probably `super_secret_password`.

Indeed, running the program with this password, we do get the flag:

<details>
<summary>Spoiler Alert: Solution</summary>

```sh
$ ./crackme2 super_secret_password
Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
``` 

<details>

### Static Solution

We can also perform a completely static solution. Let go through the assemly code line by line. 
The following lines show the checks at the start of the program that are performed to check whether it is being called with a single command-line argument (i.e. 2 command-line arguments in total):

```asm
int main (int argc, char **argv, char **envp);
; var int32_t var_ch @ stack - 0xc
; arg char **argv @ stack + 0x4
0x0804849b      lea   ecx, [argv]
0x0804849f      and   esp, 0xfffffff0
0x080484a2      push  dword [ecx - 4]
0x080484a5      push  ebp
0x080484a6      mov   ebp, esp
0x080484a8      push  ecx
0x080484a9      sub   esp, 4
0x080484ac      mov   eax, ecx
0x080484ae      cmp   dword [eax], 2
0x080484b1      je    0x80484d0
0x080484b3      mov   eax, dword [eax + 4]
0x080484b6      mov   eax, dword [eax]
0x080484b8      sub   esp, 8
0x080484bb      push  eax
0x080484bc      push  str.Usage:__s_password               ; 0x8048660 ; "Usage: %s password\n" ; const char *format
0x080484c1      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
0x080484c6      add   esp, 0x10
0x080484c9      mov   eax, 1
0x080484ce      jmp   0x804851e
```

If the number of arguments is different from two, the usage message is shown and the program jumps to the leave instruction where the base pointer is restored and
the program returns. Otherwise, the program continues as follows:

```asm
│      │└─> 0x080484d0      mov   eax, dword [eax + 4]
│      │    0x080484d3      add   eax, 4
│      │    0x080484d6      mov   eax, dword [eax]
│      │    0x080484d8      sub   esp, 8
│      │    0x080484db      push  str.super_secret_password            ; 0x8048674 ; "super_secret_password" ; const char *s2
│      │    0x080484e0      push  eax                                  ; const char *s1
│      │    0x080484e1      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
│      │    0x080484e6      add   esp, 0x10
│      │    0x080484e9      test  eax, eax
│      │┌─< 0x080484eb      je    0x8048504
│      ││   0x080484ed      sub   esp, 0xc
│      ││   0x080484f0      push  str.Access_denied.                   ; 0x804868a ; "Access denied." ; const char *s
│      ││   0x080484f5      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ││   0x080484fa      add   esp, 0x10
│      ││   0x080484fd      mov   eax, 1
│     ┌───< 0x08048502      jmp   0x804851e
│     ││└─> 0x08048504      sub   esp, 0xc
│     ││    0x08048507      push  str.Access_granted.                  ; 0x8048699 ; "Access granted." ; const char *s
│     ││    0x0804850c      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│     ││    0x08048511      add   esp, 0x10
│     ││    0x08048514      call  sym.giveFlag                         ; sym.giveFlag
│     ││    0x08048519      mov   eax, 0
│     ││    ; CODE XREFS from main @ 0x80484ce, 0x8048502
│     └└──> 0x0804851e      mov   ecx, dword [var_ch]
│           0x08048521      leave
│           0x08048522      lea   esp, [ecx - 4]
└           0x08048525      ret
```

The command-line argument is then compared against the password (`super_secret_string`). If it does not match, the program exists with the message *Access denied*.
If it does match, the string *Access granted.* is written to the screen using a `puts` call. Then the flag is printed using the `sym.giveFlag` function before the program exists.

The `sym.giveFlag` function has the following disassembly code:

```asm
sym.giveFlag ();
│           ; var const char *s @ stack - 0x11f
│           ; var int32_t var_ech @ stack - 0xec
│           ; var int32_t var_20h @ stack - 0x20
│           ; var int32_t var_10h @ stack - 0x10
│           0x08048526      push  ebp
│           0x08048527      mov   ebp, esp
│           0x08048529      push  edi
│           0x0804852a      push  esi
│           0x0804852b      push  ebx
│           0x0804852c      sub   esp, 0x11c
│           0x08048532      lea   eax, [var_ech]
│           0x08048538      mov   ebx, str.:                           ; 0x80486c0 ; "%"
│           0x0804853d      mov   edx, 0x33                            ; '3' ; 51
│           0x08048542      mov   edi, eax
│           0x08048544      mov   esi, ebx
│           0x08048546      mov   ecx, edx
│           0x08048548      rep   movsd dword es:[edi], dword ptr [esi]
│           0x0804854a      sub   esp, 4
│           0x0804854d      push  0x33                                 ; '3' ; 51 ; size_t n
│           0x0804854f      push  0x41                                 ; 'A' ; 65 ; int c
│           0x08048551      lea   eax, [s]
│           0x08048557      push  eax                                  ; void *s
│           0x08048558      call  sym.imp.memset                       ; sym.imp.memset ; void *memset(void *s, int c, size_t n)
│           0x0804855d      add   esp, 0x10
│           0x08048560      mov   dword [var_20h], 0
│       ┌─< 0x08048567      jmp   0x8048598
│      ┌──> 0x08048569      lea   edx, [s]
│      ╎│   0x0804856f      mov   eax, dword [var_20h]
│      ╎│   0x08048572      add   eax, edx
│      ╎│   0x08048574      movzx eax, byte [eax]
│      ╎│   0x08048577      mov   edx, eax
│      ╎│   0x08048579      mov   eax, dword [var_20h]
│      ╎│   0x0804857c      mov   eax, dword [var_10h + 0xcx*4 - 0xe8]
│      ╎│   0x08048583      add   eax, edx
│      ╎│   0x08048585      mov   ecx, eax
│      ╎│   0x08048587      lea   edx, [s]
│      ╎│   0x0804858d      mov   eax, dword [var_20h]
│      ╎│   0x08048590      add   eax, edx
│      ╎│   0x08048592      mov   byte [eax], cl
│      ╎│   0x08048594      add   dword [var_20h], 1
│      ╎│   ; CODE XREF from sym.giveFlag @ 0x8048567
│      ╎└─> 0x08048598      mov   eax, dword [var_20h]
│      ╎    0x0804859b      cmp   eax, 0x32                            ; 50
│      └──< 0x0804859e      jbe   0x8048569
│           0x080485a0      sub   esp, 0xc
│           0x080485a3      lea   eax, [s]
│           0x080485a9      push  eax                                  ; const char *s
│           0x080485aa      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│           0x080485af      add   esp, 0x10
│           0x080485b2      nop
│           0x080485b3      lea   esp, [var_10h]
│           0x080485b6      pop   ebx
│           0x080485b7      pop   esi
│           0x080485b8      pop   edi
│           0x080485b9      pop   ebp
└           0x080485ba      ret
```

First the flag buffer is filled with 50 `A` characters. Afterwards, a loop is executed 50 times, where each character in the buffer is changed.
This is the same procedure as in `crackme1` and it can be solved with a similar python script:

```py

integers = [
"0x25",
"0x00",
"0x00",
"0x00",
"0x2B",
"0x00" ,
"0x00" ,
"0x00" ,
"0x20" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x26" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x3A" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x25" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x32" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x34" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x21" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2C" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x33" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x33" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x27" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x32" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x25" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2B" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x20" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x26" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x33" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x27" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x24" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2D" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x36" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2B" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2B" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x26" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x24" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x33" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x1E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2F" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2E" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x28" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x2D" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x33" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x32" ,
"0x00" ,
"0x00" ,
"0x00" ,
"0x3C" ,
"0x00" ,
"0x00" ,
"0x00" ,
 ]

for idx, i in enumerate(integers):
    if idx % 4 == 0:
        c = chr(int(i, 16) + ord('A'))
        print(c, end="")

print()
```
which gives the flag:

<details>
<summary>Spoiler Alert: Solution</summary>

```sh
$ python3 integers.py 
flag{if_i_submit_this_flag_then_i_will_get_points}
```

</details>

### Static Decompiler

The previous solution was purely based on the disassembly. We can also use the decompiler in Ghidra to get the source code. After a bit of manipulation and variable-renaming, the main function looks like we would expect from our previous analysis:

```c

int main(int argc,char **argv)

{
  int var_tmp_control;
  
  if (argc == 2) {
    var_tmp_control = strcmp(argv[1],"super_secret_password");
    if (var_tmp_control == 0) {
      puts("Access granted.");
      giveFlag();
      var_tmp_control = 0;
    }
    else {
      puts("Access denied.");
      var_tmp_control = 1;
    }
  }
  else {
    printf("Usage: %s password\n",*argv);
    var_tmp_control = 1;
  }
  return var_tmp_control;
}
```

and the `giveFlag` function's source code looks as follows:

```c
void giveFlag(void)

{
  int iVar1;
  int *offsets;
  int *puVar2;
  char mw_str_flag_buf [51];
  int local_ec [51];
  uint var_loop;
  
  offsets = &INT_080486c0;
  puVar2 = local_ec;
  for (iVar1 = 0x33; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *offsets;
    offsets = offsets + 1;
    puVar2 = puVar2 + 1;
  }
  memset(mw_str_flag_buf,L'A',51);
  for (var_loop = 0; var_loop < 51; var_loop = var_loop + 1) {
    mw_str_flag_buf[var_loop] = (char)local_ec[var_loop] + mw_str_flag_buf[var_loop];
  }
  puts(mw_str_flag_buf);
  return;
}
```
