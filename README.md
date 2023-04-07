# py-assembler
Python script that can assemble and disassemble x86/x64 assembly. It requires `gcc 64bit` to be installed and has no other dependencies.

## Usage
To use py-assembler, you need to open a terminal and run the script with the appropriate command and parameters. The available commands are:

### Assemble
To assemble instructions, here is an example use of the command:

```css
py main.py -a x64 -t assemble -c "mov al, 1; ret"
or
py main.py -a x64 -t assemble -f "path/to/file"
```

The `-a/--arch` parameter specifies the architecture of the instructions you want to assemble, and can be either `x86` or `x64`.

The `-t/--type` parameter specifies that you want to assemble instructions.

You can provide the instructions either as a string using `-c/--code`, or as a file path using `-f/--file`.

### Disassemble
To disassemble instructions, here is an example use of the command:

```css
py main.py -a x64 -t disassemble -c "b0 01 c3"
or
py main.py -a x64 -t disassemble -f "path/to/file"
```

The `-a/--arch` parameter specifies the architecture of the instructions you want to disassemble, and can be either `x86` or `x64`.

The `-t/--type` parameter specifies that you want to disassemble instructions.

You can provide the instructions either as a string using `-c/--code`, or as a file path using `-f/--file`.

## Acknowledgements
I would like to thank [`Taylor Hornby`](https://github.com/defuse).