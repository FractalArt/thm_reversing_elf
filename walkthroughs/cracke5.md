# Reversing ELF

This is a writeup of the `crackme5` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 166b7011c111cd44693a38197ff35b03

## Solution

### Static Solution in Assembly

This crackme is straightforward to solve in assembly:

```asm
┌ int main (int argc, char **argv, char **envp);
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; var char **var_78h @ stack - 0x78
│           ; var int var_6ch @ stack - 0x6c
│           ; var unsigned long var_5ch @ stack - 0x5c
│           ; var const char *var_addr_user_pwd @ stack - 0x58
│           ; var const char *s2 @ stack - 0x38
│           ; var int64_t var_30h @ stack - 0x30
│           ; var int64_t var_2fh @ stack - 0x2f
│           ; var int64_t var_2eh @ stack - 0x2e
│           ; var int64_t var_2dh @ stack - 0x2d
│           ; var int64_t var_2ch @ stack - 0x2c
│           ; var int64_t var_2bh @ stack - 0x2b
│           ; var int64_t var_2ah @ stack - 0x2a
│           ; var int64_t var_29h @ stack - 0x29
│           ; var int64_t var_28h @ stack - 0x28
│           ; var int64_t var_27h @ stack - 0x27
│           ; var int64_t var_26h @ stack - 0x26
│           ; var int64_t var_25h @ stack - 0x25
│           ; var int64_t var_24h @ stack - 0x24
│           ; var int64_t var_23h @ stack - 0x23
│           ; var int64_t var_22h @ stack - 0x22
│           ; var int64_t var_21h @ stack - 0x21
│           ; var int64_t var_20h @ stack - 0x20
│           ; var int64_t var_1fh @ stack - 0x1f
│           ; var int64_t var_1eh @ stack - 0x1e
│           ; var int64_t var_1dh @ stack - 0x1d
│           ; var int64_t canary @ stack - 0x10
│           0x00400773      push  rbp
│           0x00400774      mov   rbp, rsp
│           0x00400777      sub   rsp, 0x70
│           0x0040077b      mov   dword [var_6ch], edi                 ; argc
│           0x0040077e      mov   qword [var_78h], rsi                 ; argv
│           0x00400782      mov   rax, qword fs:[0x28]
│           0x0040078b      mov   qword [canary], rax
│           0x0040078f      xor   eax, eax
│           0x00400791      mov   byte [s2], 0x4f                      ; 'O' ; 79
│           0x00400795      mov   byte [s2 + 0x1], 0x66                ; 'f' ; 102
│           0x00400799      mov   byte [s2 + 0x2], 0x64                ; 'd' ; 100
│           0x0040079d      mov   byte [s2 + 0x3], 0x6c                ; 'l' ; 108
│           0x004007a1      mov   byte [s2 + 0x4], 0x44                ; 'D' ; 68
│           0x004007a5      mov   byte [s2 + 0x5], 0x53                ; 'S' ; 83
│           0x004007a9      mov   byte [s2 + 0x6], 0x41                ; 'A' ; 65
│           0x004007ad      mov   byte [s2 + 0x7], 0x7c                ; '|' ; 124
│           0x004007b1      mov   byte [var_30h], 0x33                 ; '3' ; 51
│           0x004007b5      mov   byte [var_2fh], 0x74                 ; 't' ; 116
│           0x004007b9      mov   byte [var_2eh], 0x58                 ; 'X' ; 88
│           0x004007bd      mov   byte [var_2dh], 0x62                 ; 'b' ; 98
│           0x004007c1      mov   byte [var_2ch], 0x33                 ; '3' ; 51
│           0x004007c5      mov   byte [var_2bh], 0x32                 ; '2' ; 50
│           0x004007c9      mov   byte [var_2ah], 0x7e                 ; '~' ; 126
│           0x004007cd      mov   byte [var_29h], 0x58                 ; 'X' ; 88
│           0x004007d1      mov   byte [var_28h], 0x33                 ; '3' ; 51
│           0x004007d5      mov   byte [var_27h], 0x74                 ; 't' ; 116
│           0x004007d9      mov   byte [var_26h], 0x58                 ; 'X' ; 88
│           0x004007dd      mov   byte [var_25h], 0x40                 ; '@' ; 64
│           0x004007e1      mov   byte [var_24h], 0x73                 ; 's' ; 115
│           0x004007e5      mov   byte [var_23h], 0x58                 ; 'X' ; 88
│           0x004007e9      mov   byte [var_22h], 0x60                 ; '`' ; 96
│           0x004007ed      mov   byte [var_21h], 0x34                 ; '4' ; 52
│           0x004007f1      mov   byte [var_20h], 0x74                 ; 't' ; 116
│           0x004007f5      mov   byte [var_1fh], 0x58                 ; 'X' ; 88
│           0x004007f9      mov   byte [var_1eh], 0x74                 ; 't' ; 116
│           0x004007fd      mov   byte [var_1dh], 0x7a                 ; 'z' ; 122
│           0x00400801      mov   edi, str.Enter_your_input:           ; 0x400954 ; "Enter your input:" ; const char *s
│           0x00400806      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│           0x0040080b      lea   rax, [var_addr_user_pwd]
│           0x0040080f      mov   rsi, rax
│           0x00400812      mov   edi, data.00400966                   ; 0x400966 ; "%s" ; const char *format
│           0x00400817      mov   eax, 0
│           0x0040081c      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x00400821      lea   rdx, [s2]
│           0x00400825      lea   rax, [var_addr_user_pwd]
│           0x00400829      mov   rsi, rdx                             ; const char *s2
│           0x0040082c      mov   rdi, rax                             ; const char *s1
│           0x0040082f      call  sym.strcmp                           ; sym.strcmp ; int strcmp(const char *s1, const char *s2)
│           0x00400834      mov   dword [var_5ch], eax
│           0x00400837      cmp   dword [var_5ch], 0
│       ┌─< 0x0040083b      jne   0x400849
│       │   0x0040083d      mov   edi, str.Good_game                   ; 0x400969 ; "Good game" ; const char *s
│       │   0x00400842      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ┌──< 0x00400847      jmp   0x400853
│      │└─> 0x00400849      mov   edi, str.Always_dig_deeper           ; 0x400973 ; "Always dig deeper" ; const char *s
│      │    0x0040084e      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      │    ; CODE XREF from main @ 0x400847
│      └──> 0x00400853      mov   eax, 0
│           0x00400858      mov   rcx, qword [canary]
│           0x0040085c      xor   rcx, qword fs:[0x28]
│       ┌─< 0x00400865      je    0x40086c
│       │   0x00400867      call  sym.imp.__stack_chk_fail             ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x0040086c      leave
└           0x0040086d      ret
```

First the user is asked to enter his password which is then read using `scanf` into a char array with base address `var_add_user_pwd`.
After that it is compared to `s2` using `strcmp`. If the password is correct, the message "Good game" is displayed, else "Always dig deeper".

The last thing to do is to extract the password from the assembly. It is stored in `s2` which has base address, `stack - 0x38`. 

The following piece seems to construct the password and store it in an array starting at the base address of `s2`:


```asm
0x00400791      mov   byte [s2], 0x4f                      ; 'O' ; 79
0x00400795      mov   byte [s2 + 0x1], 0x66                ; 'f' ; 102
0x00400799      mov   byte [s2 + 0x2], 0x64                ; 'd' ; 100
0x0040079d      mov   byte [s2 + 0x3], 0x6c                ; 'l' ; 108
0x004007a1      mov   byte [s2 + 0x4], 0x44                ; 'D' ; 68
0x004007a5      mov   byte [s2 + 0x5], 0x53                ; 'S' ; 83
0x004007a9      mov   byte [s2 + 0x6], 0x41                ; 'A' ; 65
0x004007ad      mov   byte [s2 + 0x7], 0x7c                ; '|' ; 124
0x004007b1      mov   byte [var_30h], 0x33                 ; '3' ; 51
0x004007b5      mov   byte [var_2fh], 0x74                 ; 't' ; 116
0x004007b9      mov   byte [var_2eh], 0x58                 ; 'X' ; 88
0x004007bd      mov   byte [var_2dh], 0x62                 ; 'b' ; 98
0x004007c1      mov   byte [var_2ch], 0x33                 ; '3' ; 51
0x004007c5      mov   byte [var_2bh], 0x32                 ; '2' ; 50
0x004007c9      mov   byte [var_2ah], 0x7e                 ; '~' ; 126
0x004007cd      mov   byte [var_29h], 0x58                 ; 'X' ; 88
0x004007d1      mov   byte [var_28h], 0x33                 ; '3' ; 51
0x004007d5      mov   byte [var_27h], 0x74                 ; 't' ; 116
0x004007d9      mov   byte [var_26h], 0x58                 ; 'X' ; 88
0x004007dd      mov   byte [var_25h], 0x40                 ; '@' ; 64
0x004007e1      mov   byte [var_24h], 0x73                 ; 's' ; 115
0x004007e5      mov   byte [var_23h], 0x58                 ; 'X' ; 88
0x004007e9      mov   byte [var_22h], 0x60                 ; '`' ; 96
0x004007ed      mov   byte [var_21h], 0x34                 ; '4' ; 52
0x004007f1      mov   byte [var_20h], 0x74                 ; 't' ; 116
0x004007f5      mov   byte [var_1fh], 0x58                 ; 'X' ; 88
0x004007f9      mov   byte [var_1eh], 0x74                 ; 't' ; 116
0x004007fd      mov   byte [var_1dh], 0x7a                 ; 'z' ; 122
```

Thus the password is:

<details>

<summary>Spoiler Alert: Solution</summary>

```
OfdlDSA|3tXb32~X3tX@sX`4tXtz
```

</details>
