# Reversing ELF

This is a writeup of the `crackme1` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 058f218fc4796705afbc845b63e1b5ea

## Solution

### Dynamic Solution

This is a very simple crackme. The only thing that needs to be done is to make the file executable and run it in a virtual environment to make it reveal the flag:


<details>

<summary>Spoiler Alert: Solution</summary>

```sh
> chmod +x crackme1
> ./crackme1
flag{not_that_kind_of_elf}
```

</details>

### Static Solution Disassembler

The previous solution was static. One can also find the flag purely through reverse engineering by loading it into `radare2`:

```sh
> radare2 crackme1
[0x00400450]> aaa 
[0x00400450]> s sym.main
[0x00400546]> pdf
```

This prints the disassembly of the main function. 

The code for setting up the flag string is the following:

```asm
0x0040061b      488d8570ffff.  lea rax, [s]
0x00400622      ba1b000000     mov edx, 0x1b               ; 27 ; size_t n
0x00400627      be41000000     mov esi, 0x41               ; 'A' ; 65 ; int c
0x0040062c      4889c7         mov rdi, rax                ; void *s
0x0040062f      e8ecfdffff     call sym.imp.memset         ; void *memset(void*s, int c, size_t n)
```

This creates a string with 27 `A` characters.

After that, we find a loop that modifies the string before printing it to the terminal:

```asm
│           0x0040062f      e8ecfdffff     call sym.imp.memset         ; void *memset(void 
*s, int c, size_t n)
│           0x00400634      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x0040063b      eb2c           jmp 0x400669
│       │   ; CODE XREF from main @ 0x40066f
│      ┌──> 0x0040063d      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x00400640      4898           cdqe
│      ╎│   0x00400642      0fb6840570ff.  movzx eax, byte [rbp + rax - 0x90]
│      ╎│   0x0040064a      89c2           mov edx, eax
│      ╎│   0x0040064c      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0040064f      4898           cdqe
│      ╎│   0x00400651      8b448590       mov eax, dword [rbp + rax*4 - 0x70]
│      ╎│   0x00400655      01d0           add eax, edx
│      ╎│   0x00400657      89c2           mov edx, eax
│      ╎│   0x00400659      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0040065c      4898           cdqe
│      ╎│   0x0040065e      88940570ffff.  mov byte [rbp + rax - 0x90], dl
│      ╎│   0x00400665      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from main @ 0x40063b
│      ╎└─> 0x00400669      8b45fc         mov eax, dword [var_4h]
│      ╎    0x0040066c      83f81a         cmp eax, 0x1a               ; 26
│      └──< 0x0040066f      76cc           jbe 0x40063d
│           0x00400671      488d8570ffff.  lea rax, [s]
│           0x00400678      4889c7         mov rdi, rax                ; const char *s
│           0x0040067b      e890fdffff     call sym.imp.puts           ; int puts(const cha
```

Notice that `var_4h` is the loop variable, so let us rename it for clarity:

```sh
[0x00400546]> afvn var_idx var_4h
```

Then, at the start of the loop, the loop index variable is initialized to zero and we jump to the instructions that check the loop condition: (`jmp 0x400669`)

```
0x00400634      c745fc000000.  mov dword [var_idx], 0
0x0040063b      eb2c           jmp 0x400669
```

The check  verifies if the index variable is smaller or equal than 26 (another indication that our flag is composed of 27 characters, consistent with the `memset` call above).

```asm
0x00400669      8b45fc         mov eax, dword [var_idx]
0x0040066c      83f81a         cmp eax, 0x1a               ; 26
0x0040066f      76cc           jbe 0x40063d
```

If the loop index is below or equal (`be`) we jump (`jbe`) to the loop body, otherwise execution continues.

The instructions for the loop body are below:

```asm
0x0040063d      8b45fc         mov eax, dword [var_idx]
0x00400640      4898           cdqe
0x00400642      0fb6840570ff.  movzx eax, byte [rbp + rax - 0x90]
0x0040064a      89c2           mov edx, eax
0x0040064c      8b45fc         mov eax, dword [var_idx]
0x0040064f      4898           cdqe
0x00400651      8b448590       mov eax, dword [rbp + rax*4 - 0x70]
0x00400655      01d0           add eax, edx
0x00400657      89c2           mov edx, eax
0x00400659      8b45fc         mov eax, dword [var_idx]
0x0040065c      4898           cdqe
0x0040065e      88940570ffff.  mov byte [rbp + rax - 0x90], dl
0x00400665      8345fc01       add dword [var_idx], 1
```

The first step is to move a store the index variable in `eax` and then retrieve a specific byte from the stack, the first one (if the loop value is 0) being `[rbp - 0x90]`, the second being (if the loop value is 1) `[rbp + 1 - 0x90]`. The result is stored in `edx`. 

Notice, from [this stackoverflow article](https://stackoverflow.com/questions/54618685/what-is-the-meaning-use-of-the-movzx-cdqe-instructions-in-this-code-output-by-a) that `cdqe` means:

*The CDQE instruction sign-extends a DWORD (32-bit value) in the EAX register to a QWORD (64-bit value) in the RAX register.*

Furthermore, in the same article, it is explained that 

*The MOVZX instruction zero-extends the source to the destination. In this case, it zero-extends the BYTE loaded from memory at [rbp + rax - 0x90] to the DWORD destination register, EAX.*

The values that are copied are therefore the positions in the string `s` which are all uppercase `A`s (from `memset`).

Then, we again move the loop index into the eax register, extend it to `DWORD` using `cdqe` and then extract shift offsets from the stack variables:

```arm
0x0040064c      8b45fc         mov eax, dword [var_idx]
0x0040064f      4898           cdqe
0x00400651      8b448590       mov eax, dword [rbp + rax*4 - 0x70]
0x00400655      01d0           add eax, edx
```

The offsets stored on the stack are defined here:

```asm
0x0040055e      c74590250000.  mov dword [var_70h], 0x25   ; '%' ; 37
0x00400565      c745942b0000.  mov dword [var_6ch], 0x2b   ; '+' ; 43
0x0040056c      c74598200000.  mov dword [var_68h], 0x20   ; 32
0x00400573      c7459c260000.  mov dword [var_64h], 0x26   ; '&' ; 38
0x0040057a      c745a03a0000.  mov dword [var_60h], 0x3a   ; ':' ; 58
0x00400581      c745a42d0000.  mov dword [var_5ch], 0x2d   ; '-' ; 45
0x00400588      c745a82e0000.  mov dword [var_58h], 0x2e   ; '.' ; 46
0x0040058f      c745ac330000.  mov dword [var_54h], 0x33   ; '3' ; 51
0x00400596      c745b01e0000.  mov dword [var_50h], 0x1e   ; 30
0x0040059d      c745b4330000.  mov dword [var_4ch], 0x33   ; '3' ; 51
0x004005a4      c745b8270000.  mov dword [var_48h], 0x27   ; ''' ; 39
0x004005ab      c745bc200000.  mov dword [var_44h], 0x20   ; 32
0x004005b2      c745c0330000.  mov dword [var_40h], 0x33   ; '3' ; 51
0x004005b9      c745c41e0000.  mov dword [var_3ch], 0x1e   ; 30
0x004005c0      c745c82a0000.  mov dword [var_38h], 0x2a   ; '*' ; 42
0x004005c7      c745cc280000.  mov dword [var_34h], 0x28   ; '(' ; 40
0x004005ce      c745d02d0000.  mov dword [var_30h], 0x2d   ; '-' ; 45
0x004005d5      c745d4230000.  mov dword [var_2ch], 0x23   ; '#' ; 35
0x004005dc      c745d81e0000.  mov dword [var_28h], 0x1e   ; 30
0x004005e3      c745dc2e0000.  mov dword [var_24h], 0x2e   ; '.' ; 46
0x004005ea      c745e0250000.  mov dword [var_20h], 0x25   ; '%' ; 37
0x004005f1      c745e41e0000.  mov dword [var_1ch], 0x1e   ; 30
0x004005f8      c745e8240000.  mov dword [var_18h], 0x24   ; '$' ; 36
0x004005ff      c745ec2b0000.  mov dword [var_14h], 0x2b   ; '+' ; 43
0x00400606      c745f0250000.  mov dword [var_10h], 0x25   ; '%' ; 37
0x0040060d      c745f43c0000.  mov dword [var_ch],  0x3c    ; '<' ; 60
0x00400614      c745f8bfffff.  mov dword [var_8h], 0xffffffbf ; 4294967231
```

We can therefore use the following python script to get the flag:

```py
offsets = ["0x25",
"0x2b",
"0x20",
"0x26",
"0x3a",
"0x2d",
"0x2e",
"0x33",
"0x1e",
"0x33",
"0x27",
"0x20",
"0x33",
"0x1e",
"0x2a",
"0x28",
"0x2d",
"0x23",
"0x1e",
"0x2e",
"0x25",
"0x1e",
"0x24",
"0x2b",
"0x25",
"0x3c",
]

for offset in offsets:
    print(chr(int(offset, 16) + ord('A')), end="")

print()

```

and it gives what we have already found from executing the crackme binary:

<details>
  <summary> Spoiler Alert: Solution</summary>

```sh
>  python3 generate_flag.py 
flag{not_that_kind_of_elf}
```

</details>

### Static Solution Decompiler

In the previous static solution, we did the reverse engineering solely based on the disassembly code.
We can simplify the process, if we load the binary into `Ghidra` and use the decompiler to get high-level C-code.
After renaming the variables and adjusting the types, we get the following code for the main function, which closely matches
what we found in the disassembly analysis:

```c
int main(void)

{
  char mw_var_flag_buffer [32];
  int mw_var_offset_array [27];
  uint mw_var_loop;
  
  mw_var_offset_array[0] = 0x25;
  mw_var_offset_array[1] = 0x2b;
  mw_var_offset_array[2] = 0x20;
  mw_var_offset_array[3] = 0x26;
  mw_var_offset_array[4] = 0x3a;
  mw_var_offset_array[5] = 0x2d;
  mw_var_offset_array[6] = 0x2e;
  mw_var_offset_array[7] = 0x33;
  mw_var_offset_array[8] = 0x1e;
  mw_var_offset_array[9] = 0x33;
  mw_var_offset_array[10] = 0x27;
  mw_var_offset_array[11] = 0x20;
  mw_var_offset_array[12] = 0x33;
  mw_var_offset_array[13] = 0x1e;
  mw_var_offset_array[14] = 0x2a;
  mw_var_offset_array[15] = 0x28;
  mw_var_offset_array[16] = 0x2d;
  mw_var_offset_array[17] = 0x23;
  mw_var_offset_array[18] = 0x1e;
  mw_var_offset_array[19] = 0x2e;
  mw_var_offset_array[20] = 0x25;
  mw_var_offset_array[21] = 0x1e;
  mw_var_offset_array[22] = 0x24;
  mw_var_offset_array[23] = 0x2b;
  mw_var_offset_array[24] = 0x25;
  mw_var_offset_array[25] = 0x3c;
  mw_var_offset_array[26] = -0x41;
  memset(mw_var_flag_buffer,L'A',27);
  for (mw_var_loop = 0; mw_var_loop < 27; mw_var_loop = mw_var_loop + 1) {
    mw_var_flag_buffer[(int)mw_var_loop] =
         (char)mw_var_offset_array[(int)mw_var_loop] + mw_var_flag_buffer[(int)mw_var_loop];
  }
  puts(mw_var_flag_buffer);
  return 0;
}
```
