# Reversing ELF Walkthroughs

This repository contains my writeups for the eight crackmes of the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

My goal was to familiarize myself with *assembly* language, which is why the focus of most write-ups is on this aspect. 

This means that my solutions are probably not the easiest possible or shortest ones. 

In some cases I also describe how to easily get the flag 
using simple static tools such as the `strings` command or `Ghidra`'s powerful decompiler. In other cases I show how the flag can
be easily obtained dynamically, for example by executing the binary, running it through `ltrace` (to find `strcmp`) calls or by manipulation of the instruction pointer.

