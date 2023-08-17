# Reversing ELF

This is a writeup of the `crackme6` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 14cf8faef0305f684e5733d2a91f069c

## Solution

### Static solution

We derive the solution based on the disassembly shown in `rizin`. The main functions code is shown below:

```asm
┌ int main (int argc, char **argv, char **envp);
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; var const char **var_ptr_ptr_ptr_argv @ stack - 0x18
│           ; var uint64_t var_ptr_argc @ stack - 0xc
│           0x00400711      push  rbp
│           0x00400712      mov   rbp, rsp
│           0x00400715      sub   rsp, 0x10
│           0x00400719      mov   dword [var_ptr_argc], edi            ; argc
│           0x0040071c      mov   qword [var_ptr_ptr_ptr_argv], rsi    ; argv
│           0x00400720      cmp   dword [var_ptr_argc], 2              ; check if there is a command-line argument
│       ┌─< 0x00400724      je    0x400741
│       │   0x00400726      mov   rax, qword [var_ptr_ptr_ptr_argv]
│       │   0x0040072a      mov   rax, qword [rax]
│       │   0x0040072d      mov   rsi, rax
│       │   0x00400730      mov   edi, str.Usage_:__s_password_Good_luck__read_the_source ; 0x400810 ; "Usage : %s password\nGood luck, read the source\n" ; const char *format
│       │   0x00400735      mov   eax, 0
│       │   0x0040073a      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│      ┌──< 0x0040073f      jmp   0x400754
│      │└─> 0x00400741      mov   rax, qword [var_ptr_ptr_ptr_argv]
│      │    0x00400745      add   rax, 8                               ; address of the second command-line argument
│      │    0x00400749      mov   rax, qword [rax]                     ; store the address of the second command line argument in rax, then move to rdi
│      │    0x0040074c      mov   rdi, rax                             ; int64_t arg1
│      │    0x0040074f      call  sym.compare_pwd                      ; sym.compare_pwd
│      │    ; CODE XREF from main @ 0x40073f
│      └──> 0x00400754      mov   eax, 0
│           0x00400759      leave
└           0x0040075a      ret
```

The program checks the requirement that a command-line argument needs to be provided (`0x00400720`).
If this is not the case, an error message is shown (`0x0040073a`).
If a user password is provided on the command-line, the address of `argv` is added to the `rax` register (`0x00400741`),
which is then increased by 8 to point at the address of the second command-line argument (`0x00400745`).
The address of the second command-line argument is then moved to rdi where it is passed to the function `compare_pwd`.

The code of the function `compare_pwd` looks like:

```asm
sym.compare_pwd (const char **arg1);
│           ; arg const char **arg1 @ rdi
│           ; var const char **var_ptr_ptr_user_pwd @ stack - 0x10
│           0x004006d1      push  rbp
│           0x004006d2      mov   rbp, rsp
│           0x004006d5      sub   rsp, 0x10
│           0x004006d9      mov   qword [var_ptr_ptr_user_pwd], rdi    ; arg1
│           0x004006dd      mov   rax, qword [var_ptr_ptr_user_pwd]
│           0x004006e1      mov   rdi, rax                             ; int64_t arg1
│           0x004006e4      call  sym.my_secure_test                   ; sym.my_secure_test
│           0x004006e9      test  eax, eax                             ; if the password of my_secure_test is 0, the password was correct
│       ┌─< 0x004006eb      jne   0x4006f9
│       │   0x004006ed      mov   edi, str.password_OK                 ; 0x4007e8 ; "password OK" ; const char *s
│       │   0x004006f2      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ┌──< 0x004006f7      jmp   0x40070f
│      │└─> 0x004006f9      mov   rax, qword [var_ptr_ptr_user_pwd]
│      │    0x004006fd      mov   rsi, rax
│      │    0x00400700      mov   edi, str.password___s__not_OK        ; 0x4007f4 ; "password \"%s\" not OK\n" ; const char *format
│      │    0x00400705      mov   eax, 0
│      │    0x0040070a      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│      │    ; CODE XREF from sym.compare_pwd @ 0x4006f7
│      └──> 0x0040070f      leave
└           0x00400710      ret
```

The address of the user password is passed as argument and is stored in `rdi` before being passed to `sym.my_secure_test`.
If this function returns 0 (`0x004006e9` to `0x004006f2`), the message "password OK" is printed. Else an error message is shown.

The only thing left to do, is to reverse engineer what the function `my_secure_test` does. Its disassembly looks like:

```asm
sym.my_secure_test (const char **arg1);
│           ; arg const char **arg1 @ rdi
│           ; var const char **var_addr_ptr_user_pwd @ stack - 0x10
│           0x0040057d      push  rbp
│           0x0040057e      mov   rbp, rsp
│           0x00400581      mov   qword [var_addr_ptr_user_pwd], rdi   ; arg1
│           0x00400585      mov   rax, qword [var_addr_ptr_user_pwd]
│           0x00400589      movzx eax, byte [rax]
│           0x0040058c      test  al, al                               ; Require al != 0
│       ┌─< 0x0040058e      je    0x40059b
│       │   0x00400590      mov   rax, qword [var_addr_ptr_user_pwd]
│       │   0x00400594      movzx eax, byte [rax]
│       │   0x00400597      cmp   al, 0x31                             ; 49 ; require pwd[0] == 0x31
│      ┌──< 0x00400599      je    0x4005a5
│      │└─> 0x0040059b      mov   eax, 0xffffffff                      ; -1
│      │┌─< 0x004005a0      jmp   0x4006cf
│      └──> 0x004005a5      mov   rax, qword [var_addr_ptr_user_pwd]
│       │   0x004005a9      add   rax, 1
│       │   0x004005ad      movzx eax, byte [rax]
│       │   0x004005b0      test  al, al                               ; require pwd[1] != 0
│      ┌──< 0x004005b2      je    0x4005c3
│      ││   0x004005b4      mov   rax, qword [var_addr_ptr_user_pwd]
│      ││   0x004005b8      add   rax, 1
│      ││   0x004005bc      movzx eax, byte [rax]
│      ││   0x004005bf      cmp   al, 0x33                             ; 51 ; require pwd[1] == 0x33
│     ┌───< 0x004005c1      je    0x4005cd
│     │└──> 0x004005c3      mov   eax, 0xffffffff                      ; -1
│     │┌──< 0x004005c8      jmp   0x4006cf
│     └───> 0x004005cd      mov   rax, qword [var_addr_ptr_user_pwd]
│      ││   0x004005d1      add   rax, 2
│      ││   0x004005d5      movzx eax, byte [rax]
│      ││   0x004005d8      test  al, al                               ; require pwd[2] != 0
│     ┌───< 0x004005da      je    0x4005eb
│     │││   0x004005dc      mov   rax, qword [var_addr_ptr_user_pwd]
│     │││   0x004005e0      add   rax, 2
│     │││   0x004005e4      movzx eax, byte [rax]
│     │││   0x004005e7      cmp   al, 0x33                             ; 51 ; pwd[2] == 0x33
│    ┌────< 0x004005e9      je    0x4005f5
│    │└───> 0x004005eb      mov   eax, 0xffffffff                      ; -1
│    │┌───< 0x004005f0      jmp   0x4006cf
│    └────> 0x004005f5      mov   rax, qword [var_addr_ptr_user_pwd]
│     │││   0x004005f9      add   rax, 3
│     │││   0x004005fd      movzx eax, byte [rax]
│     │││   0x00400600      test  al, al                               ; pwd[3] != 0
│    ┌────< 0x00400602      je    0x400613
│    ││││   0x00400604      mov   rax, qword [var_addr_ptr_user_pwd]
│    ││││   0x00400608      add   rax, 3
│    ││││   0x0040060c      movzx eax, byte [rax]
│    ││││   0x0040060f      cmp   al, 0x37                             ; 55 ; pwd[3] == 0x37
│   ┌─────< 0x00400611      je    0x40061d
│   │└────> 0x00400613      mov   eax, 0xffffffff                      ; -1
│   │┌────< 0x00400618      jmp   0x4006cf
│   └─────> 0x0040061d      mov   rax, qword [var_addr_ptr_user_pwd]
│    ││││   0x00400621      add   rax, 4
│    ││││   0x00400625      movzx eax, byte [rax]
│    ││││   0x00400628      test  al, al                               ; pwd[4] != 0
│   ┌─────< 0x0040062a      je    0x40063b
│   │││││   0x0040062c      mov   rax, qword [var_addr_ptr_user_pwd]
│   │││││   0x00400630      add   rax, 4
│   │││││   0x00400634      movzx eax, byte [rax]
│   │││││   0x00400637      cmp   al, 0x5f                             ; 95 ; pwd[4] == 0x5f
│  ┌──────< 0x00400639      je    0x400645
│  │└─────> 0x0040063b      mov   eax, 0xffffffff                      ; -1
│  │┌─────< 0x00400640      jmp   0x4006cf
│  └──────> 0x00400645      mov   rax, qword [var_addr_ptr_user_pwd]
│   │││││   0x00400649      add   rax, 5
│   │││││   0x0040064d      movzx eax, byte [rax]
│   │││││   0x00400650      test  al, al                               ; pwd[5] != 0
│  ┌──────< 0x00400652      je    0x400663
│  ││││││   0x00400654      mov   rax, qword [var_addr_ptr_user_pwd]
│  ││││││   0x00400658      add   rax, 5
│  ││││││   0x0040065c      movzx eax, byte [rax]
│  ││││││   0x0040065f      cmp   al, 0x70                             ; 112 ; pwd[5] == 0x70
│ ┌───────< 0x00400661      je    0x40066a
│ │└──────> 0x00400663      mov   eax, 0xffffffff                      ; -1
│ │┌──────< 0x00400668      jmp   0x4006cf
│ └───────> 0x0040066a      mov   rax, qword [var_addr_ptr_user_pwd]
│  ││││││   0x0040066e      add   rax, 6
│  ││││││   0x00400672      movzx eax, byte [rax]
│  ││││││   0x00400675      test  al, al                               ; pwd[6] != 0
│ ┌───────< 0x00400677      je    0x400688
│ │││││││   0x00400679      mov   rax, qword [var_addr_ptr_user_pwd]
│ │││││││   0x0040067d      add   rax, 6
│ │││││││   0x00400681      movzx eax, byte [rax]
│ │││││││   0x00400684      cmp   al, 0x77                             ; 119 ; pwd[6] == 0x77
│ ────────< 0x00400686      je    0x40068f
│ └───────> 0x00400688      mov   eax, 0xffffffff                      ; -1
│ ┌───────< 0x0040068d      jmp   0x4006cf
│ ────────> 0x0040068f      mov   rax, qword [var_addr_ptr_user_pwd]
│ │││││││   0x00400693      add   rax, 7
│ │││││││   0x00400697      movzx eax, byte [rax]
│ │││││││   0x0040069a      test  al, al                               ; pwd[7] != 0
│ ────────< 0x0040069c      je    0x4006ad
│ │││││││   0x0040069e      mov   rax, qword [var_addr_ptr_user_pwd]
│ │││││││   0x004006a2      add   rax, 7
│ │││││││   0x004006a6      movzx eax, byte [rax]
│ │││││││   0x004006a9      cmp   al, 0x64                             ; 100 ; pwd[7] == 0x64
│ ────────< 0x004006ab      je    0x4006b4
│ ────────> 0x004006ad      mov   eax, 0xffffffff                      ; -1
│ ────────< 0x004006b2      jmp   0x4006cf
│ ────────> 0x004006b4      mov   rax, qword [var_addr_ptr_user_pwd]
│ │││││││   0x004006b8      add   rax, 8
│ │││││││   0x004006bc      movzx eax, byte [rax]
│ │││││││   0x004006bf      test  al, al                               ; pwd[8] == 0 (end of the string)
│ ────────< 0x004006c1      je    0x4006ca
│ │││││││   0x004006c3      mov   eax, 0xffffffff                      ; -1
│ ────────< 0x004006c8      jmp   0x4006cf
│ ────────> 0x004006ca      mov   eax, 0
│ │││││││   ; XREFS: CODE 0x004005a0  CODE 0x004005c8  CODE 0x004005f0  CODE 0x00400618  CODE 0x00400640  CODE 0x00400668  
│ │││││││   ; XREFS: CODE 0x0040068d  CODE 0x004006b2  CODE 0x004006c8  
│ └└└└└└└─> 0x004006cf      pop   rbp
└           0x004006d0      ret
```

At first sight, this looks very complicated, but from the comments we added in `rizin` we can see that it is just a bunch of if clauses. If any but the last (`pwd[8]`) is zero, the code sets the value of the `eax` register to `-1` and jumps to `0x4006cf` where the program ends and returns `-1` (i.e. the check fails).

If the checked bytes are different from 0, a check for a specific byte content is performed and if it passes, one moves on to the same checks for the following byte until the last byte is required to be `0` (the end of the string):

```asm
0x004006b4      mov   rax, qword [var_addr_ptr_user_pwd]
0x004006b8      add   rax, 8
0x004006bc      movzx eax, byte [rax]
0x004006bf      test  al, al                               ; pwd[8] == 0 (end of the string)
0x004006c1      je    0x4006ca
0x004006c3      mov   eax, 0xffffffff                      ; -1
0x004006c8      jmp   0x4006cf
0x004006ca      mov   eax, 0
```

When this is the case, the `eax` register is set to 0 and the function returns (i.e. the password check passed).

Hence, we can conclude that the password has to be the following sequence of bytes (omitted the final 0):

<details>

<summary> Spoiler alert: Solution</summary>

```
0x31 0x33 0x33 0x37 0x5f 0x70 0x77 0x64
```

Using the `From Hex` transformation in `CyberChef`, we find that the password is: `1337_pwd`. Indeed running the crackme binary with this password we get positive feedback:

```sh
$ ./crackme6 1337_pwd
password OK
```

</details>

