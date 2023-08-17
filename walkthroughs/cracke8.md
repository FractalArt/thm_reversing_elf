# Reversing ELF

This is a writeup of the `crackme8` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: ba29836fe17423f055ab08f7e1c7b282

## Solution

### Dynamic Solution

In this case, the dynamic approach does not give any low-hanging fruits. None of these approaches worked:

- strings
- ltrace

However, in the disassembly of the main function, we see the following instruction:

```asm
0x08048512      call  sym.giveFlag
```

What we can therefore do is:

1. Load the crackme in `rizin`
2. Set a breakpoint at the *main* function (`db @ main`)
3. Start the debugger with a random password (`ood password`)
4. Continue execution until we hit the breakpoint (`dc`)
5. Set the instruction pointer to the address of the `giveFlag` function (`dr eip=0x08048512`)
6. Continue the execution (`dc`)

This completely bypasses the check for the password that the user needs to provide (only some password needs to be present) and immediately prints the flag:

<details>

<summary>Spoiler Alert: Solution</summary>

```sh
$ rizin crackme8 
 -- The unix-like reverse engineering framework.
[0x080483a0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls
[x] Analyze len bytes of instructions for references
[x] Check for classes
[x] Analyze local variables and arguments
[x] Type matching analysis for all functions
[x] Applied 0 FLIRT signatures via sigdb
[x] Propagate noreturn information
[x] Resolve pointers to data sections
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x080483a0]> db @ main
[0x080483a0]> ood password
ERROR: rz-run: invalid @<num>@ in `@im=ibus`
ERROR: rz-run: invalid hexpair string `1.80`
ERROR: rz-run: invalid hexpair string `0`
Process with PID 8269 started...
ERROR: File dbg:///path/to/crackme8 "password" reopened in read-write mode
[0xf7f0e120]> dc
hit breakpoint at: 0x804849b
[0x0804849b]> dr eip=0x08048512
[0x0804849b]> dc
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
[+] SIGNAL 11 errno=0 addr=0xfffffffc code=1 si_pid=-4 ret=0
```

</details>



### Static Solution

The main function's disassembly looks like:

```asm
┌ int main (int argc, char **argv, char **envp);
│           ; var int32_t var_ch @ stack - 0xc
│           ; arg char **argv @ stack + 0x4
│           0x0804849b      lea   ecx, [argv]
│           0x0804849f      and   esp, 0xfffffff0
│           0x080484a2      push  dword [ecx - 4]
│           0x080484a5      push  ebp
│           0x080484a6      mov   ebp, esp
│           0x080484a8      push  ecx
│           0x080484a9      sub   esp, 4
│           0x080484ac      mov   eax, ecx
│           0x080484ae      cmp   dword [eax], 2
│       ┌─< 0x080484b1      je    0x80484d0
│       │   0x080484b3      mov   eax, dword [eax + 4]
│       │   0x080484b6      mov   eax, dword [eax]
│       │   0x080484b8      sub   esp, 8
│       │   0x080484bb      push  eax
│       │   0x080484bc      push  str.Usage:__s_password               ; 0x8048660 ; "Usage: %s password\n" ; const char *format
│       │   0x080484c1      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│       │   0x080484c6      add   esp, 0x10
│       │   0x080484c9      mov   eax, 1
│      ┌──< 0x080484ce      jmp   0x804851c
│      │└─> 0x080484d0      mov   eax, dword [eax + 4]
│      │    0x080484d3      add   eax, 4
│      │    0x080484d6      mov   eax, dword [eax]
│      │    0x080484d8      sub   esp, 0xc
│      │    0x080484db      push  eax                                  ; const char *str
│      │    0x080484dc      call  sym.imp.atoi                         ; sym.imp.atoi ; int atoi(const char *str)
│      │    0x080484e1      add   esp, 0x10
│      │    0x080484e4      cmp   eax, 0xcafef00d
│      │┌─< 0x080484e9      je    0x8048502
│      ││   0x080484eb      sub   esp, 0xc
│      ││   0x080484ee      push  str.Access_denied.                   ; 0x8048674 ; "Access denied." ; const char *s
│      ││   0x080484f3      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ││   0x080484f8      add   esp, 0x10
│      ││   0x080484fb      mov   eax, 1
│     ┌───< 0x08048500      jmp   0x804851c
│     ││└─> 0x08048502      sub   esp, 0xc
│     ││    0x08048505      push  str.Access_granted.                  ; 0x8048683 ; "Access granted." ; const char *s
│     ││    0x0804850a      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│     ││    0x0804850f      add   esp, 0x10
│     ││    0x08048512      call  sym.giveFlag                         ; sym.giveFlag
│     ││    0x08048517      mov   eax, 0
│     ││    ; CODE XREFS from main @ 0x80484ce, 0x8048500
│     └└──> 0x0804851c      mov   ecx, dword [var_ch]
│           0x0804851f      leave
│           0x08048520      lea   esp, [ecx - 4]
└           0x08048523      ret
```

The code first checks if an obligatory command-line argument was passed and if not, it prints an error / usage message and exits.

If a command-line argument is passed, it is converted to an integer (`0x080484dc call sym.imp.atoi`).
If the result matches `0xcafef00d` (`0x080484e4 cmp eax, 0xcafef00d`), then the message "Access granted." is printed (else "Access denied.") and the flag is shown using the method `sym.getFlag()`.

Converting `cafef00d` to integer gives `3405705229`. This is larger than the maximal 32 bit integer value:

```py
>>> 2**32 / 2
2147483648.0
```

so we need to take the corresponding negative number, i.e. the two complement: `-889262067`.

Indeed using this password gives the flag:

<details>
<summary>Spoiler Alert: Solution</summary>

```sh
$ ./crackme8  -889262067
Access granted.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```

</details>

We can also extract the flag statically from the function `giveFlag` whose disassembly is given by:

```asm
┌ sym.giveFlag ();
│           ; var const char *s @ stack - 0x14c
│           ; var int32_t var_110h @ stack - 0x110
│           ; var int32_t var_20h @ stack - 0x20
│           ; var int32_t var_10h @ stack - 0x10
│           0x08048524      push  ebp
│           0x08048525      mov   ebp, esp
│           0x08048527      push  edi
│           0x08048528      push  esi
│           0x08048529      push  ebx
│           0x0804852a      sub   esp, 0x13c
│           0x08048530      lea   eax, [var_110h]
│           0x08048536      mov   ebx, str.:_3                         ; 0x80486a0 ; "%"
│           0x0804853b      mov   edx, 0x3c                            ; '<' ; 60
│           0x08048540      mov   edi, eax
│           0x08048542      mov   esi, ebx
│           0x08048544      mov   ecx, edx
│           0x08048546      rep   movsd dword es:[edi], dword ptr [esi]
│           0x08048548      sub   esp, 4
│           0x0804854b      push  0x3c                                 ; '<' ; 60 ; size_t n
│           0x0804854d      push  0x41                                 ; 'A' ; 65 ; int c
│           0x0804854f      lea   eax, [s]
│           0x08048555      push  eax                                  ; void *s
│           0x08048556      call  sym.imp.memset                       ; sym.imp.memset ; void *memset(void *s, int c, size_t n)
│           0x0804855b      add   esp, 0x10
│           0x0804855e      mov   dword [var_20h], 0
│       ┌─< 0x08048565      jmp   0x8048596
│      ┌──> 0x08048567      lea   edx, [s]
│      ╎│   0x0804856d      mov   eax, dword [var_20h]
│      ╎│   0x08048570      add   eax, edx
│      ╎│   0x08048572      movzx eax, byte [eax]
│      ╎│   0x08048575      mov   edx, eax
│      ╎│   0x08048577      mov   eax, dword [var_20h]
│      ╎│   0x0804857a      mov   eax, dword [var_10h + 0xcx*4 - 0x10c]
│      ╎│   0x08048581      add   eax, edx
│      ╎│   0x08048583      mov   ecx, eax
│      ╎│   0x08048585      lea   edx, [s]
│      ╎│   0x0804858b      mov   eax, dword [var_20h]
│      ╎│   0x0804858e      add   eax, edx
│      ╎│   0x08048590      mov   byte [eax], cl
│      ╎│   0x08048592      add   dword [var_20h], 1
│      ╎│   ; CODE XREF from sym.giveFlag @ 0x8048565
│      ╎└─> 0x08048596      mov   eax, dword [var_20h]
│      ╎    0x08048599      cmp   eax, 0x3b                            ; 59
│      └──< 0x0804859c      jbe   0x8048567
│           0x0804859e      sub   esp, 0xc
│           0x080485a1      lea   eax, [s]
│           0x080485a7      push  eax                                  ; const char *s
│           0x080485a8      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│           0x080485ad      add   esp, 0x10
│           0x080485b0      nop
│           0x080485b1      lea   esp, [var_10h]
│           0x080485b4      pop   ebx
│           0x080485b5      pop   esi
│           0x080485b6      pop   edi
│           0x080485b7      pop   ebp
└           0x080485b8      ret
```

First, a pointer to a list of offsets at `0x80486a0` is stored in ebx (then is esi). 
The `rep` (*repeat*) instruction consults the `ecx` register to see that `60` double word 
moves need to performed that take bytes located at `esi` (the offsets) and stores them in 
the segment `es` at offset `edi` (`[var_110h]`).

Then a 60-char default flag filled with `A`-characters is created using `memset` at the address `s`.

```
0x08048536      mov   ebx, str.:_3                         ; 0x80486a0 ; "%"
0x0804853b      mov   edx, 0x3c                            ; '<' ; 60
0x08048540      mov   edi, eax
0x08048542      mov   esi, ebx
0x08048544      mov   ecx, edx
0x08048546      rep   movsd dword es:[edi], dword ptr [esi]
0x08048548      sub   esp, 4
0x0804854b      push  0x3c                                 ; '<' ; 60 ; size_t n
0x0804854d      push  0x41                                 ; 'A' ; 65 ; int c
0x0804854f      lea   eax, [s]
0x08048555      push  eax                                  ; void *s
0x08048556      call  sym.imp.memset                       ; sym.imp.memset ; void *memset(void *s, int c, size_t n)
```

Once this is done, each default char is shifted by an offset to give the final flag.

We can look at the content of the memory address `0x80486a0` to extract the offsets:

```sh
[0x08048524]> s 0x80486a0
[0x080486a0]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x080486a0  2500 0000 2b00 0000 2000 0000 2600 0000  %...+... ...&...
0x080486b0  3a00 0000 2000 0000 3300 0000 1e00 0000  :... ...3.......
0x080486c0  2b00 0000 2400 0000 2000 0000 3200 0000  +...$... ...2...
0x080486d0  3300 0000 1e00 0000 3300 0000 2700 0000  3.......3...'...
0x080486e0  2800 0000 3200 0000 1e00 0000 2200 0000  (...2......."...
0x080486f0  2000 0000 2500 0000 2400 0000 1e00 0000   ...%...$.......
0x08048700  3600 0000 2e00 0000 2d00 0000 3300 0000  6.......-...3...
0x08048710  1e00 0000 2b00 0000 2400 0000 2000 0000  ....+...$... ...
0x08048720  2a00 0000 1e00 0000 3800 0000 2e00 0000  *.......8.......
0x08048730  3400 0000 3100 0000 1e00 0000 2200 0000  4...1......."...
0x08048740  3100 0000 2400 0000 2300 0000 2800 0000  1...$...#...(...
0x08048750  3300 0000 1e00 0000 2200 0000 2000 0000  3......."... ...
0x08048760  3100 0000 2300 0000 1e00 0000 2d00 0000  1...#.......-...
0x08048770  3400 0000 2c00 0000 2100 0000 2400 0000  4...,...!...$...
0x08048780  3100 0000 3200 0000 3c00 0000 bfff ffff  1...2...<.......
0x08048790  011b 033b 3000 0000 0500 0000 a0fb ffff  ...;0...........
```

We can use these offsets to generate the following `Python` password generating code:

```py
integers = [
    '0x25',
    '0x2b',
    '0x20',
    '0x26',
    '0x3a',
    '0x20',
    '0x33',
    '0x1e',
    '0x2b',
    '0x24',
    '0x20',
    '0x32',
    '0x33',
    '0x1e',
    '0x33',
    '0x27',
    '0x28',
    '0x32',
    '0x1e',
    '0x22',
    '0x20',
    '0x25',
    '0x24',
    '0x1e',
    '0x36',
    '0x2e',
    '0x2d',
    '0x33',
    '0x1e',
    '0x2b',
    '0x24',
    '0x20',
    '0x2a',
    '0x1e',
    '0x38',
    '0x2e',
    '0x34',
    '0x31',
    '0x1e',
    '0x22',
    '0x31',
    '0x24',
    '0x23',
    '0x28',
    '0x33',
    '0x1e',
    '0x22',
    '0x20',
    '0x31',
    '0x23',
    '0x1e',
    '0x2d',
    '0x34',
    '0x2c',
    '0x21',
    '0x24',
    '0x31',
    '0x32',
    '0x3c'
]

for i in integers:
    i_dec = int(i, 16)
    print(chr(ord('A') + i_dec), end='')
print()
```

<details>
<summary>Spoiler Alert: Solution</summary>
Executing this script gives the flag:

```sh
$ python3 gen_pwd.py 
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```

</details>
