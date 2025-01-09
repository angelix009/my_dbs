# My Debugging Suite

A debugging suite containing three tools: my_nm, my_strace, and my_db.

## my_nm

Located in the `my_nm` directory, this tool displays the symbol table of an ELF file.

### Installation

```bash
cd my_nm
make
```

### Usage

```bash
./my_nm <file>
```

Output format for each symbol:
```
<address> <size> <type> <bind> <vis> <section> <name>
```

Example:
```bash
./my_nm example.o
0000000000000000 20 STT_FUNC STB_GLOBAL STV_DEFAULT .text do_calc
0000000000000014 94 STT_FUNC STB_GLOBAL STV_DEFAULT .text main
0000000000000000 0 STT_NOTYPE STB_GLOBAL STV_DEFAULT UND printf
```

## my_strace

Located in the `my_strace` directory, this tool traces system calls made by a program.

### Installation

```bash
cd my_strace
make
```

### Usage

```bash
./my_strace <program>
```

Output format:
```
syscall_name(arguments) = return_value
```

Example:
```bash
./my_strace /bin/ls
brk() = 93860181577728
access() = -1
openat(fd = AT_FDCWD, path = "/etc/ld.so.cache", oflags = O_RDONLY|O_CLOEXEC) = 3
...
```

## my_db

Located in the `my_db` directory, this is a simple debugger for ELF executables.

### Installation

```bash
cd my_db
make
```

### Usage

```bash
./my_db <program>
```

### Available Commands

#### Basic Commands
- `quit` or `q`: Exit the debugger
- `kill`: Kill the debugged process
- `continue`: Continue execution
- `registers`: Display CPU registers

#### Memory Inspection
```bash
x <count> <address>    # Display memory in hexadecimal
d <count> <address>    # Display memory in signed decimal
u <count> <address>    # Display memory in unsigned decimal
```

#### Breakpoint Management
```bash
break <address|symbol>  # Set breakpoint
blist                  # List breakpoints
bdel <number>          # Delete breakpoint
```

#### Example Session
```bash
> ./my_db test
> break func1
Point d'arrêt ajouté à 0x401775
> continue
Breakpoint at 0x401775
> registers
rax: 0x12
...
> continue
test1
Programme terminé avec le code 0
```

## Building Test Programs

To compile programs for debugging:
```bash
gcc -std=c99 -pedantic -Wall -Wextra -Wvla -Werror -static program.c -o program
```

## Important Notes

- All programs expect ELF format files
- Test programs should be compiled with `-static` flag
- ASLR should be disabled for consistent debugging results
