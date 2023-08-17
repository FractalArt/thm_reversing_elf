# Reversing ELF

This is a writeup of the `crackme7` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 13d84bcf74b9f608fba84f17a4db3fe8

## Solution

### Dynamic Analysis

We just do a short dynamic analysis to get a feel for what the program does by executing it in a sandbox:

```sh
$ ./crackme7 
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 
```

### Static Solution in Assembly

When looking at the main function in disassembly, it has a lot of branching:

```asm
 int main (int argc, char **argv, char **envp);
│           ; var const char *var_80h @ stack - 0x80
│           ; var int var_1ch @ stack - 0x1c
│           ; var int var_18h @ stack - 0x18
│           ; var int var_14h @ stack - 0x14
│           ; var int32_t var_10h @ stack - 0x10
│           ; arg char **argv @ stack + 0x4
│           0x080484bb      lea   ecx, [argv]
│           0x080484bf      and   esp, 0xfffffff0
│           0x080484c2      push  dword [ecx - 4]
│           0x080484c5      push  ebp
│           0x080484c6      mov   ebp, esp
│           0x080484c8      push  edi
│           0x080484c9      push  ecx
│           0x080484ca      sub   esp, 0x70
│           ; CODE XREFS from main @ 0x8048590, 0x8048643
│      ┌┌─> 0x080484cd      sub   esp, 0xc
│      ╎╎   0x080484d0      push  str.Menu:___1__Say_hello__2__Add_numbers__3__Quit ; 0x80487e0 ; "Menu:\n\n[1] Say hello\n[2] Add numbers\n[3] Quit" ; const char *s
│      ╎╎   0x080484d5      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│      ╎╎   0x080484da      add   esp, 0x10
│      ╎╎   0x080484dd      sub   esp, 0xc
│      ╎╎   0x080484e0      push  str.                                 ; 0x804880e ; "\n[>] " ; const char *format
│      ╎╎   0x080484e5      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│      ╎╎   0x080484ea      add   esp, 0x10
│      ╎╎   0x080484ed      sub   esp, 8
│      ╎╎   0x080484f0      lea   eax, [var_14h]
│      ╎╎   0x080484f3      push  eax
│      ╎╎   0x080484f4      push  data.08048814                        ; 0x8048814 ; "%u" ; const char *format
│      ╎╎   0x080484f9      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      ╎╎   0x080484fe      add   esp, 0x10
│      ╎╎   0x08048501      cmp   eax, 1                               ; 1
│     ┌───< 0x08048504      je    0x8048520
│     │╎╎   0x08048506      sub   esp, 0xc
│     │╎╎   0x08048509      push  str.Unknown_input                    ; 0x8048817 ; "Unknown input!" ; const char *s
│     │╎╎   0x0804850e      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│     │╎╎   0x08048513      add   esp, 0x10
│     │╎╎   0x08048516      mov   eax, 1
│    ┌────< 0x0804851b      jmp   0x804869c
│    │└───> 0x08048520      mov   eax, dword [var_14h]
│    │ ╎╎   0x08048523      cmp   eax, 1                               ; 1
│    │┌───< 0x08048526      jne   0x8048595
│    ││╎╎   0x08048528      sub   esp, 0xc
│    ││╎╎   0x0804852b      push  str.What_is_your_name                ; 0x8048826 ; "What is your name? " ; const char *format
│    ││╎╎   0x08048530      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│    ││╎╎   0x08048535      add   esp, 0x10
│    ││╎╎   0x08048538      lea   edx, [var_80h]
│    ││╎╎   0x0804853b      mov   eax, 0
│    ││╎╎   0x08048540      mov   ecx, 0x19                            ; 25
│    ││╎╎   0x08048545      mov   edi, edx
│    ││╎╎   0x08048547      rep   stosd dword es:[edi], eax
│    ││╎╎   0x08048549      sub   esp, 8
│    ││╎╎   0x0804854c      lea   eax, [var_80h]
│    ││╎╎   0x0804854f      push  eax
│    ││╎╎   0x08048550      push  str.99s                              ; 0x804883a ; "%99s" ; const char *format
│    ││╎╎   0x08048555      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│    ││╎╎   0x0804855a      add   esp, 0x10
│    ││╎╎   0x0804855d      cmp   eax, 1                               ; 1
│   ┌─────< 0x08048560      je    0x804857c
│   │││╎╎   0x08048562      sub   esp, 0xc
│   │││╎╎   0x08048565      push  str.Unable_to_read_name              ; 0x804883f ; "Unable to read name!" ; const char *s
│   │││╎╎   0x0804856a      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│   │││╎╎   0x0804856f      add   esp, 0x10
│   │││╎╎   0x08048572      mov   eax, 1
│  ┌──────< 0x08048577      jmp   0x804869c
│  │└─────> 0x0804857c      sub   esp, 8
│  │ ││╎╎   0x0804857f      lea   eax, [var_80h]
│  │ ││╎╎   0x08048582      push  eax
│  │ ││╎╎   0x08048583      push  str.Hello___s                        ; 0x8048854 ; "Hello, %s!\n" ; const char *format
│  │ ││╎╎   0x08048588      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│  │ ││╎╎   0x0804858d      add   esp, 0x10
│  │ ││└──< 0x08048590      jmp   0x80484cd
│  │ │└───> 0x08048595      mov   eax, dword [var_14h]
│  │ │  ╎   0x08048598      cmp   eax, 2                               ; 2
│  │ │ ┌──< 0x0804859b      jne   0x8048648
│  │ │ │╎   0x080485a1      sub   esp, 0xc
│  │ │ │╎   0x080485a4      push  str.Enter_first_number:              ; 0x8048860 ; "Enter first number: " ; const char *format
│  │ │ │╎   0x080485a9      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│  │ │ │╎   0x080485ae      add   esp, 0x10
│  │ │ │╎   0x080485b1      sub   esp, 8
│  │ │ │╎   0x080485b4      lea   eax, [var_18h]
│  │ │ │╎   0x080485b7      push  eax
│  │ │ │╎   0x080485b8      push  data.08048875                        ; 0x8048875 ; "%d" ; const char *format
│  │ │ │╎   0x080485bd      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│  │ │ │╎   0x080485c2      add   esp, 0x10
│  │ │ │╎   0x080485c5      cmp   eax, 1                               ; 1
│  │ │┌───< 0x080485c8      je    0x80485e4
│  │ │││╎   0x080485ca      sub   esp, 0xc
│  │ │││╎   0x080485cd      push  str.Unable_to_read_number            ; 0x8048878 ; "Unable to read number!" ; const char *s
│  │ │││╎   0x080485d2      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│  │ │││╎   0x080485d7      add   esp, 0x10
│  │ │││╎   0x080485da      mov   eax, 1
│  │┌─────< 0x080485df      jmp   0x804869c
│  │││└───> 0x080485e4      sub   esp, 0xc
│  │││ │╎   0x080485e7      push  str.Enter_second_number:             ; 0x804888f ; "Enter second number: " ; const char *format
│  │││ │╎   0x080485ec      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│  │││ │╎   0x080485f1      add   esp, 0x10
│  │││ │╎   0x080485f4      sub   esp, 8
│  │││ │╎   0x080485f7      lea   eax, [var_1ch]
│  │││ │╎   0x080485fa      push  eax
│  │││ │╎   0x080485fb      push  data.08048875                        ; 0x8048875 ; "%d" ; const char *format
│  │││ │╎   0x08048600      call  sym.imp.__isoc99_scanf               ; sym.imp.__isoc99_scanf ; int scanf(const char *format)
│  │││ │╎   0x08048605      add   esp, 0x10
│  │││ │╎   0x08048608      cmp   eax, 1                               ; 1
│  │││┌───< 0x0804860b      je    0x8048624
│  │││││╎   0x0804860d      sub   esp, 0xc
│  │││││╎   0x08048610      push  str.Unable_to_read_number            ; 0x8048878 ; "Unable to read number!" ; const char *s
│  │││││╎   0x08048615      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│  │││││╎   0x0804861a      add   esp, 0x10
│  │││││╎   0x0804861d      mov   eax, 1
│ ┌───────< 0x08048622      jmp   0x804869c
│ ││││└───> 0x08048624      mov   edx, dword [var_18h]
│ ││││ │╎   0x08048627      mov   eax, dword [var_1ch]
│ ││││ │╎   0x0804862a      lea   ecx, [edx + eax]
│ ││││ │╎   0x0804862d      mov   edx, dword [var_1ch]
│ ││││ │╎   0x08048630      mov   eax, dword [var_18h]
│ ││││ │╎   0x08048633      push  ecx
│ ││││ │╎   0x08048634      push  edx
│ ││││ │╎   0x08048635      push  eax
│ ││││ │╎   0x08048636      push  str.d____d____d                      ; 0x80488a5 ; "%d + %d = %d\n" ; const char *format
│ ││││ │╎   0x0804863b      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│ ││││ │╎   0x08048640      add   esp, 0x10
│ ││││ │└─< 0x08048643      jmp   0x80484cd
│ ││││ └──> 0x08048648      mov   eax, dword [var_14h]
│ ││││      0x0804864b      cmp   eax, 3                               ; 3
│ ││││  ┌─< 0x0804864e      jne   0x8048662
│ ││││  │   0x08048650      sub   esp, 0xc
│ ││││  │   0x08048653      push  str.Goodbye                          ; 0x80488b3 ; "Goodbye!" ; const char *s
│ ││││  │   0x08048658      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│ ││││  │   0x0804865d      add   esp, 0x10
│ ││││ ┌──< 0x08048660      jmp   0x8048697
│ ││││ │└─> 0x08048662      mov   eax, dword [var_14h]
│ ││││ │    0x08048665      cmp   eax, 0x7a69
│ ││││ │┌─< 0x0804866a      jne   0x8048683
│ ││││ ││   0x0804866c      sub   esp, 0xc
│ ││││ ││   0x0804866f      push  str.Wow_such_h4x0r                   ; 0x80488bc ; "Wow such h4x0r!" ; const char *s
│ ││││ ││   0x08048674      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
│ ││││ ││   0x08048679      add   esp, 0x10
│ ││││ ││   0x0804867c      call  sym.giveFlag                         ; sym.giveFlag
│ ││││┌───< 0x08048681      jmp   0x8048697
│ ││││││└─> 0x08048683      mov   eax, dword [var_14h]
│ ││││││    0x08048686      sub   esp, 8
│ ││││││    0x08048689      push  eax
│ ││││││    0x0804868a      push  str.Unknown_choice:__d               ; 0x80488cc ; "Unknown choice: %d\n" ; const char *format
│ ││││││    0x0804868f      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
│ ││││││    0x08048694      add   esp, 0x10
│ ││││││    ; CODE XREFS from main @ 0x8048660, 0x8048681
│ ││││└└──> 0x08048697      mov   eax, 0
│ ││││      ; CODE XREFS from main @ 0x804851b, 0x8048577, 0x80485df, 0x8048622
│ └└└└────> 0x0804869c      lea   esp, [var_10h]
│           0x0804869f      pop   ecx
│           0x080486a0      pop   edi
│           0x080486a1      pop   ebp
│           0x080486a2      lea   esp, [ecx - 4]
└           0x080486a5      ret
```

However, we can see the spot where the flag is being printed:

```asm
 0x0804866f      push  str.Wow_such_h4x0r                   ; 0x80488bc ; "Wow such h4x0r!" ; const char *s
 0x08048674      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
 0x08048679      add   esp, 0x10
 0x0804867c      call  sym.giveFlag                         ; sym.giveFlag
 0x08048681      jmp   0x8048697
 0x08048683      mov   eax, dword [var_14h]
 0x08048686      sub   esp, 8
 0x08048689      push  eax
 0x0804868a      push  str.Unknown_choice:__d               ; 0x80488cc ; "Unknown choice: %d\n" ; const char *format
 0x0804868f      call  sym.imp.printf                       ; sym.imp.printf ; int printf(const char *format)
```

To see how can reach this spot through user input from the prompt obtained when launching the crackme binary, we can look at the disassembly in `rizin`s graph mode and move our way up.

```sh
$ rizin crackme7 
 -- Find hexpairs with '/x a0 cc 33'
[0x080483c0]> aaa
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
[0x080483c0]> s main
[0x080484bb]> VV
```

What we see is the following:

- First, the menu is presented to the user (`0x080484d0`)
- Then the user input is read using `scanf` (`0x080484f9`)
- Then it is checked whether reading the input was successful (`0x08048501`)
- If not, an error message is shown (`0x08048509`)
- Then it is checked if the user selected "Say Hello":

```asm
 0x08048523      cmp   eax, 1                               ; 1
 0x08048526      jne   0x8048595
 0x08048528      sub   esp, 0xc
 0x0804852b      push  str.What_is_your_name                ; 0x8048826 ; "What is your name? " ; const char *format
```

When this is not the case (as we are looking for from `rizin`s graph mode), we move on to `0x8048595` where we the user would have selected "Add numbers":

```asm
0x08048598      cmp   eax, 2                               ; 2
0x0804859b      jne   0x8048648
0x080485a1      sub   esp, 0xc
0x080485a4      push  str.Enter_first_number:              ; 0x8048860 ; "Enter first number: " ; const char *format
```

From `rizin`s graph view, this is still not the case leading us to the `h4x0r` output, so we move on to `0x8048648` which corresponds to the user selecting `Quit` in the menu:


```asm
 0x08048648      mov   eax, dword [var_14h]
 0x0804864b      cmp   eax, 3                               ; 3
 0x0804864e      jne   0x8048662
 0x08048650      sub   esp, 0xc
 0x08048653      push  str.Goodbye                          ; 0x80488b3 ; "Goodbye!" ; const char *s
```

Given that this is still not what we want, we move on to `0x8048662`:

```asm
0x08048662      mov   eax, dword [var_14h]
0x08048665      cmp   eax, 0x7a69
0x0804866a      jne   0x8048683
0x0804866c      sub   esp, 0xc
0x0804866f      push  str.Wow_such_h4x0r                   ; 0x80488bc ; "Wow such h4x0r!" ; const char *s
0x08048674      call  sym.imp.puts                         ; sym.imp.puts ; int puts(const char *s)
0x08048679      add   esp, 0x10
0x0804867c      call  sym.giveFlag                         ; sym.giveFlag
0x08048681      jmp   0x8048697
```

Here, we can see that in order to arrive at this spot, we have to enter (the non-listed) option `0x7a69` as choice, which corresponds to:

<details>

<summary>Spoiler Alert: Solution</summary>

```sh
$ rz-ax 0x7a69
31337
```

Trying this out, we do indeed get the flag:

```sh
$ ./crackme7 
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 31337
Wow such h4x0r!
flag{much_reversing_very_ida_wow}
```

</details>

The only thing missing in our analysis is how the flag is actually constructed in the function `sym.giveFlag`. This function has the following code:


Opening the function in `Ghidra` and cleaning the decompiled code up, we end up with:

```c
void giveFlag(void)

{
  int iVar1;
  int *offsets;
  int *piVar2;
  char flag [34];
  int offsets_cpy [34];
  uint i;
  
  offsets = &INT_080488e0;
  piVar2 = offsets_cpy;
  for (iVar1 = 0x22; iVar1 != 0; iVar1 = iVar1 + -1) {
    *piVar2 = *offsets;
    offsets = offsets + 1;
    piVar2 = piVar2 + 1;
  }
  memset(flag,L'A',34);
  for (i = 0; i < 34; i = i + 1) {
    flag[i] = (char)offsets_cpy[i] + flag[i];
  }
  puts(flag);
  return;
}
```

Hence we see that a tempory flag is constructed out of 34 'A' characters. Then each of these characters is shifted by an offset stored in `INT_080488e0`. Taking these offsets from 
Ghidra, we can generate the password using this python script:

```py
integers = [
    "25h",
    "2Bh",
    "20h",
    "26h",
    "3Ah",
    "2Ch",
    "34h",
    "22h",
    "27h",
    "1Eh",
    "31h",
    "24h",
    "35h",
    "24h",
    "31h",
    "32h",
    "28h",
    "2Dh",
    "26h",
    "1Eh",
    "35h",
    "24h",
    "31h",
    "38h",
    "1Eh",
    "28h",
    "23h",
    "20h",
    "1Eh",
    "36h",
    "2Eh",
    "36h",
    "3Ch"
]

for i in integers:
    i_dec = int(f'0x{i[:-1]}', 16)

    print(chr(ord('A') + i_dec), end="")

print()
```

From the Ghidra code we can see that the first offset is stored at: `080488e0`.  This address can be found in `rizin` as well:

```asm
0x080486b8      mov   ebx, str.:_4                         ; 0x80488e0 ; "%"
0x080486bd      mov   edx, 0x22                            ; '"' ; 34
0x080486c2      mov   edi, eax
0x080486c4      mov   esi, ebx
0x080486c6      mov   ecx, edx
0x080486c8      rep   movsd dword es:[edi], dword ptr [esi]
```

This means that there will be 34 (`ecx`) repeated (`rep`) operations where double-word sized data pointed to by an address stored in `esi` will be moved (`movesd` = move doubleword) to the `es` segment at `edi` offset.

Figuring out the password generation from the disassembly looks quite complicated compared to the previous representation of the same algorithm that we have seen in previous crackme's.
