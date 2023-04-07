#!python3

from argparse import ArgumentParser
import os
import re
import subprocess

BOLD_START = "\033[1m"
BOLD_END = "\033[0m"

def bold(str):
  return f'{BOLD_START}{str}{BOLD_END}'

class Assembler:
  def __init__(self, arch) -> None:
    if arch == 'x86':
      self.arch = '-m32'
    else:
      self.arch = '-m64'
      
    self.input = ''
    self.compiled = []
    pass
  
  def print_errors(self, response):
    for d in response.split('\n'):
      if 'Error:' in d:
        print(d[d.find('Error:'):])
      if 'Warning:' in d:
        print(d[d.find('Warning:'):])
    pass
  
  def remove_nops(self):
    nops = 0
    lines = self.input.split('\n')
    for i in reversed(lines):
      if i == 'nop':
        nops += 1
      else:
        break
    
    stop = False
    def determine(x):
      nonlocal stop, nops
      
      if len(x) == 0:
        return True
      
      if stop:
        return False
      
      if 'nop' in x:
        if nops == 0:
          return True
        else:
          nops = nops - 1
      else:
        stop = True
      return False

    self.compiled = [x for x in reversed(self.compiled) if not determine(x)]
    self.compiled.reverse()
    pass
  
  def is_code(self, line):
    return re.search("^\s*\w+:\s+(\w{2}\s+){0,}\w+\s+.*$", line)
  
  def is_byte(self, data):
    return len(data) == 2 and 0x00 <= int(data, 16) <= 0xFF
  
  def get_instr_count(self, raw):
    return sum(1 for item in raw if self.is_byte(item))
  
  def get_longest_instr(self):
    return max(
        len(' '.join(filter(self.is_byte, line.split()[1:])))
        for line in self.compiled if self.is_code(line)
    ) if self.compiled else 0
  
  def print_compiled(self):
    line_num = 0
    max_length = self.get_longest_instr()

    print(bold('Compiled:'))
    for line in self.compiled:
      if self.is_code(line):
        raw = line.split()
        raw.pop(0)

        instructions = ' '.join(x for x in raw if self.is_byte(x))
        opcodes = ' '.join(x for x in raw if not self.is_byte(x)).replace(',', ', ')
        instr_count = self.get_instr_count(raw)
        spaces = ' ' * (max_length - len(instructions))

        print(f'  {hex(line_num)[2:]}:\t{instructions}{spaces}\t{opcodes}')
        line_num += instr_count
  
  def get_instruction_list(self):
    instruction_list = []
    for line in self.compiled:
      if self.is_code(line):
        raw = line.split()
        raw.pop(0);
        
        stop = False
        def valid(x):
          nonlocal stop
          if stop:
            return False
        
          if self.is_byte(x):
            return True
          
          stop = True
          return False
        
        instruction_list.extend([x for x in raw if valid(x)])
    return instruction_list
  
  def print_raw_bytes(self):
    instruction_list = self.get_instruction_list()

    print(bold('\nString Literal:'))
    print('"' + ''.join(f'\\x{int(byte, 16):02X}' for byte in instruction_list) + '"')

    print(bold('\nArray Literal:'))
    print('{ ' + ', '.join(f'0x{int(byte, 16):02X}' for byte in instruction_list) + ' }')

    print(bold('\nBuffer Literal:'))
    print(f'unsigned char data[{len(instruction_list)}] = {{ ' + ', '.join(f'0x{int(byte, 16):02X}' for byte in instruction_list) + ' };')

    print(bold('\nRaw Hex:'))
    print(''.join(f'{int(byte, 16):02X}' for byte in instruction_list))
  
  def print_use_case_cpp(self):
    instruction_list = self.get_instruction_list()

    print(bold('\nUse Case - memcpy:'))
    print(f'unsigned char data[{len(instruction_list)}] = {{ ' + ', '.join(f'0x{int(byte, 16):02X}' for byte in instruction_list) + ' };')
    print(bold('memcpy(address, data, sizeof(data));'))

    print(bold('\nUse Case - vector:'))
    print('std::vector<unsigned char> data = { ' + ', '.join(f'0x{int(byte, 16):02X}' for byte in instruction_list) + ' };')
    print(bold('memcpy(address, data.data(), data.size());'))
  
  def execute(self, input):
    self.input = input

    source = 'build/asm.s'
    output = 'build/asm.o'

    with open(source, 'w') as asm:
      asm.write(f'.intel_syntax noprefix\n_main:\n{input}\n')

    compile_cmd = f'gcc {self.arch} -c {source} -o {output}'
    objdump_cmd = f'objdump -w -z -M intel -d {output}'

    with subprocess.Popen(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) as proc:
      _, error_msg = proc.communicate()
      error_msg = error_msg.decode('utf-8')

      if not error_msg:
        with subprocess.Popen(objdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) as proc:
          output, error_msg = proc.communicate()
          output, error_msg = output.decode('utf-8'), error_msg.decode('utf-8')

          if not error_msg:
            self.compiled = output.split('\n')
            self.remove_nops()
            self.print_compiled()
            self.print_raw_bytes()
            self.print_use_case_cpp()
          else:
            self.print_errors(error_msg)
      else:
        self.print_errors(error_msg)

class Disassembler:
  def __init__(self, arch) -> None:
    self.assembler = Assembler('') # using the assembler is easier
    
    if arch == 'x86':
      self.arch = 'i386'
    else:
      self.arch = 'i386:x86-64'
    
    pass
  
  def execute(self, input):
    self.assembler.input = input

    source = 'build/asm.bin'

    with open(source, 'wb') as asm:
      asm.write(bytes.fromhex(input))

    objdump_cmd = f'objdump -w -b binary -m {self.arch} -M intel -D {source}'

    with subprocess.Popen(objdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) as proc:
      output, error_msg = proc.communicate()
      output, error_msg = output.decode('utf-8'), error_msg.decode('utf-8')

      if not error_msg:
        self.assembler.compiled = output.split('\n')
        self.assembler.remove_nops()
        self.assembler.print_compiled()
        self.assembler.print_raw_bytes()
        self.assembler.print_use_case_cpp()
      else:
        self.assembler.print_errors(error_msg)

def validate_input(args) -> tuple[bool, str]:
  if args.arch != 'x86' and args.arch != 'x64':
    return (False, 'invalid arch, only x86 and x64 are supported')
  
  if args.type != 'assemble' and args.type != 'disassemble':
    return (False, 'invalid type, only assemble and disassemble are supported')
  
  if args.code != None and args.file != None:
    return (False, 'you can use code or file, not both')
  
  if args.code == None and args.file == None:
    return (False, 'you have to specify code or file')
  
  if args.file != None:
    if not os.path.isfile(args.file):
      return (False, 'please specify a valid path')
  
  return (True, '')

def main() -> int:
  parser = ArgumentParser(
    prog='x86/x64 Assembly Compiler',
    description='A python script to generate shellcode for x64/x64 assembly')
  
  parser.add_argument('-a', '--arch')
  parser.add_argument('-t', '--type')
  parser.add_argument('-c', '--code')
  parser.add_argument('-f', '--file')
  
  args = parser.parse_args()
  if state := validate_input(args):
    if not state[0]:
      print(f'error: {state[1]}')
      return 1
    
    if args.type == 'assemble':
      inst = Assembler(args.arch)
    else:
      inst = Disassembler(args.arch)  
      
    input = ''
    if args.code != None:
      attrs = [attr.strip() for attr in args.code.split(';')] # split, e.g 'mov al, 0; ret;'
      input = '\n'.join(attrs)
    else:
      input = '\n'.join([attr.replace('\n', '') for attr in open(args.file, 'r').readlines()])
      
    if len(input) == 0:
      print('error: input was empty')
      return 1
    
    if not os.path.exists('build/'):
      os.makedirs('build')
    
    inst.execute(input)
    return 0
  
  print('error: unknown')
  return 1

if __name__ == '__main__':
  exit(main())