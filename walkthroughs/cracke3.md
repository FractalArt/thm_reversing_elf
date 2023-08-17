# Reversing ELF

This is a writeup of the `crackme3` from the `[Reversing ELF](https://tryhackme.com/room/reverselfiles)` room on TryHackMe.

## File information
- md5: 073060b5d358d4689454a419d87895da

## Solution

### Static Solution using Ghidra Decompiler

Loading the crackme binary in `Ghidra` and renaming the variables and function names we end up with the following main function:

```c
int main(int argc,char *argv)

{
  char *__s;
  size_t var_len_str;
  char *var_str_buf;
  int var_strcmp_res;
  
  if (argc == 2) {
    __s = *(char **)(argv + 4);
    var_len_str = strlen(__s);
    var_str_buf = (char *)malloc(var_len_str * 2);
    if (var_str_buf == (char *)0) {
      fwrite("malloc failed\n",0xe,1,stderr);
    }
    else {
      var_len_str = strlen(__s);
      flag_builder((int)__s,(int)var_str_buf,var_len_str,0);
      var_len_str = strlen(var_str_buf);
      if ((var_len_str == 64) &&
         (var_strcmp_res =
               strcmp(var_str_buf,"ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ=="
                     ), var_strcmp_res == 0)) {
        puts("Correct password!");
        return 0;
      }
      puts("Come on, even my aunt Mildred got this one!");
    }
  }
  else {
    fprintf(stderr,"Usage: %s PASSWORD\n",*(undefined4 *)argv);
  }
  return -1;
}
```

Even without knowing what the function `flag_builder` does, we can see that the built flag is compared against the string:

<details>
  <summary> Spoiler Alert: Solution</summary>


```
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
```

This does look suspiciously like a base-64 encoded string. Decoding it, we get:
`f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`

Executing the program with this password, we find that indeed, it is the correct one:

```sh
$ ./crackme3 f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
Correct password!
```
</details>

This also tells us what the function `flag_builder` does: it base-64 encodes the input password to be able to compare it to the target string.
