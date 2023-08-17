# Reversing ELF

This is a writeup of the `crackme4` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 30476282007c97de356e40186cf0254c

## Solution

### Dynamic Analysis

Quickly looking at the code disassembly in `rizin` we find no obvious hint at the password. 

However, the crackme can be easily solved by executing it dynamically with a random password to obtain the password using `ltrace`:

<details>
<summary> Spoiler Alert: Solution </summary>

```sh
$ ltrace ./crackme4 password
__libc_start_main(0x400716, 2, 0x7fffa8444218, 0x400760 <unfinished ...>
strcmp("my_m0r3_secur3_pwd", "password")                                                                                          = -3
printf("password "%s" not OK\n", "password"password "password" not OK
)                                                                                      = 27
+++ exited (status 0) +++
```

This tells us that the flag we are looking for is given by:


```
my_m0r3_secur3_pwd
```

</details>

### Static Analysis

Even though we found the password using dynamic analysis, we will still perform a static analysis to practice reverse engineering, reading disassembly and decompiled code.

The disassembly of the main function is straigt-forward:

```asm
│           0x00400716      push  rbp
│           0x00400717      mov   rbp, rsp
│           0x0040071a      sub   rsp, 0x10
│           0x0040071e      mov   dword [var_addr_arc], edi            ; argc
│           0x00400721      mov   qword [var_addr_argv], rsi           ; argv
│           0x00400725      cmp   dword [var_addr_arc], 2
│       ┌─< 0x00400729      je    0x400746
│       │   0x0040072b      mov   rax, qword [var_addr_argv]
│       │   0x0040072f      mov   rax, qword [rax]
│       │   0x00400732      mov   rsi, rax
│       │   0x00400735      mov   edi, str.Usage_:__s_password_This_time_the_string_is_hidden_and_we_used_strcmp ; 0x400810 ; "Usage : %s password\nThis time the string is hidden and we used strcmp\n" ; const char *format
│       │   0x0040073a      mov   eax, 0
│       │   0x0040073f      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│      ┌──< 0x00400744      jmp   0x400759
│      │└─> 0x00400746      mov   rax, qword [var_addr_argv]
│      │    0x0040074a      add   rax, 8                               ; set rax to point to the addr of the second command-line arg
│      │    0x0040074e      mov   rax, qword [rax]
│      │    0x00400751      mov   rdi, rax                             ; int64_t arg1 ; store the address of the second command-line arg in rdi and pass it to compare_pwd
│      │    0x00400754      call  sym.compare_pwd                      ; sym.compare_pwd
│      │    ; CODE XREF from main @ 0x400744
│      └──> 0x00400759      mov   eax, 0
│           0x0040075e      leave
└           0x0040075f      ret
```

First it is checked whether the user did provide a command-line argument and if not, an error message is shown.

If a command-line argument was provided, the address of argv is loaded into `rax`. Hence rax contains a pointer to `char *` pointer.
The pointer is then incremented, meaning that rax contains the base address of the char array corresponding to the second command-line argument.

The address of the second command-line argument is then moved into the `rdi` register (register containing the first function argument in x86 V ABI Linux systems) before calling
the `compare_pwd` function (i.e. the address is passed as single argument to this function).

The cleaned-up disassembly of the `compare_pwd` function looks as follows:

```asm
sym.compare_pwd (const char **var_addr_user_pwd);
│           ; arg const char **var_addr_user_pwd @ rdi
│           ; var const char **var_addr_userpwd @ stack - 0x30
│           ; var const char *var_addr_const_prt1 @ stack - 0x28
│           ; var int64_t var_addr_const_prt2 @ stack - 0x20
│           ; var int64_t var_addr_const_prt3 @ stack - 0x18
│           ; var int64_t var_addr_const_prt4 @ stack - 0x16
│           ; var int64_t canary @ stack - 0x10
│           0x0040067a      push  rbp
│           0x0040067b      mov   rbp, rsp
│           0x0040067e      sub   rsp, 0x30
│           0x00400682      mov   qword [var_addr_userpwd], rdi        ; arg1
│           0x00400686      mov   rax, qword fs:[0x28]
│           0x0040068f      mov   qword [canary], rax
│           0x00400693      xor   eax, eax
│           0x00400695      movabs rax, 0x7b175614497b5d49
│           0x0040069f      mov   qword [var_addr_const_prt1], rax
│           0x004006a3      movabs rax, 0x547b175651474157
│           0x004006ad      mov   qword [var_addr_const_prt2], rax
│           0x004006b1      mov   word [var_addr_const_prt3], 0x4053   ; 'S@'
│           0x004006b7      mov   byte [var_addr_const_prt4], 0
│           0x004006bb      lea   rax, [var_addr_const_prt1]
│           0x004006bf      mov   rdi, rax                             ; int64_t arg1
│           0x004006c2      call  sym.get_pwd                          ; sym.get_pwd
│           0x004006c7      mov   rdx, qword [var_addr_userpwd]
│           0x004006cb      lea   rax, [var_addr_const_prt1]
│           0x004006cf      mov   rsi, rdx                             ; const char *s2
│           0x004006d2      mov   rdi, rax                             ; const char *s1
│           0x004006d5      call  sym.imp.strcmp                       ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
│           0x004006da      test  eax, eax
│       ┌─< 0x004006dc      jne   0x4006ea
│       │   0x004006de      mov   edi, str.password_OK                 ; 0x4007e8 ; "password OK" ; const char *s
│       │   0x004006e3      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ┌──< 0x004006e8      jmp   0x400700
│      │└─> 0x004006ea      mov   rax, qword [var_addr_userpwd]
│      │    0x004006ee      mov   rsi, rax
│      │    0x004006f1      mov   edi, str.password___s__not_OK        ; 0x4007f4 ; "password \"%s\" not OK\n" ; const char *format
│      │    0x004006f6      mov   eax, 0
│      │    0x004006fb      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│      │    ; CODE XREF from sym.compare_pwd @ 0x4006e8
│      └──> 0x00400700      mov   rax, qword [canary]
│           0x00400704      xor   rax, qword fs:[0x28]
│       ┌─< 0x0040070d      je    0x400714
│       │   0x0040070f      call  sym.imp.__stack_chk_fail             ; sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x00400714      leave
└           0x00400715      ret
``` 

The flow is straight forward (ignoring the compiler generated canaries for the stack checks). 

Four constants are being stored on the stack:

- `0x7b175614497b5d49`
- `0x547b175651474157`
- `0x4053`
- `0`

The first variable is stored in the location `var_addr_const_prt1` whose content is then stored in `rax`, before being loaded into `rdi` and passed
to `get_pwd`. At first it seems like the other three variables are not used at all (they do not appear anywhere else in the function) but as we will see,
they are still stored on the stack and the `get_pwd` function will access them by incrementing a pointer to `var_addr_const_ptr1` to also reach these 
values.

After the call to `get_pwd` the user-provided password is passed to `rdx` (then to `rsi`) and the `var_addr_const_prt1` is loaded into `rax` (then `rdi`) before the
`strcmp` function is called, i.e. these strings are compared. When they match the string "password OK" is printed using `puts`, else an error message is printed using 
the `printf` function.

Let us now have a look at the disassembly of the `get_pwd` function.

```asm
sym.get_pwd (int64_t arg1);
│           ; arg int64_t arg1 @ rdi
│           ; var int64_t var_addr_const @ stack - 0x20
│           ; var int64_t var_addr_loop @ stack - 0xc
│           0x0040062d      push  rbp
│           0x0040062e      mov   rbp, rsp
│           0x00400631      mov   qword [var_addr_const], rdi          ; arg1
│           0x00400635      mov   dword [var_addr_loop], 0xffffffff    ; -1
│       ┌─< 0x0040063c      jmp   0x400660
│      ┌──> 0x0040063e      mov   eax, dword [var_addr_loop]
│      ╎│   0x00400641      movsxd rdx, eax
│      ╎│   0x00400644      mov   rax, qword [var_addr_const]
│      ╎│   0x00400648      add   rdx, rax
│      ╎│   0x0040064b      mov   eax, dword [var_addr_loop]
│      ╎│   0x0040064e      movsxd rcx, eax
│      ╎│   0x00400651      mov   rax, qword [var_addr_const]
│      ╎│   0x00400655      add   rax, rcx
│      ╎│   0x00400658      movzx eax, byte [rax]
│      ╎│   0x0040065b      xor   eax, 0x24                            ; 36
│      ╎│   0x0040065e      mov   byte [rdx], al
│      ╎│   ; CODE XREF from sym.get_pwd @ 0x40063c
│      ╎└─> 0x00400660      add   dword [var_addr_loop], 1
│      ╎    0x00400664      mov   eax, dword [var_addr_loop]
│      ╎    0x00400667      movsxd rdx, eax
│      ╎    0x0040066a      mov   rax, qword [var_addr_const]
│      ╎    0x0040066e      add   rax, rdx
│      ╎    0x00400671      movzx eax, byte [rax]
│      ╎    0x00400674      test  al, al
│      └──< 0x00400676      jne   0x40063e
│           0x00400678      pop   rbp
└           0x00400679      ret
```

The code stored the address of the constant from the previous function at the location `var_addr_const` and allocates space for a loop variable initialized to `-1` at
`var_addr_loop`.

Then it jumps to the loop handling instructions, where first the loop variable is incremented by one. The the constant is accessed at the byte indicated by the loop variable and it is checked whether the byte equals `0` (i.e. end of string). If this is not the case, the code continues with the loop body (`jne   0x40063e`).

There, the loop variable is first loaded into `eax`, where it is zero-extended from 32 bit to 64bit into `rdx`. On the other hand, the address of the constant value is loaded into `rax` and incremented by the  loop variable to index a specific byte. The byte is then stored in `eax` and `xor`ed with 36 and the result is stored in `rdx` (i.e. the offset location in the constant).
This is exactly where the other 3 variables in the previous function on the stack that looked like dead code are accessed:

Since the end condition for the loop is for indexed byte in the constant variable to match `0`, one can see that this only happens when the memory where the fourth variable is stored is accessed. 

In summary this function modified every byte stored in `var_addr_const` to in the contain the password. 

Using our knowledge of the password encoding (`XOR` with key `36`), we can write the password generator using the following python script:

```py
pwd = ['0x7b175614497b5d49', '0x547b175651474157', '0x4053']
# remove the `0x`, split each part into chunks of 2 and then reverse their order
pwd = [[s.replace('0x', '')[i:i+2] for i in range(0, len(s), 2)][::-1] for s in pwd]

for part in pwd:
    for b in part:
        if b == '':
            continue
        i = int(f'0x{b}', 16) ^ 36
        print(chr(i), end = '')

print()
```

Notice that the reverse is because the binary is in little-endian.
