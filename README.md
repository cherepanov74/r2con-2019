# vermu 1

We got two binary files: vermu and level1

Vermu is 64 bit macho executable, level is binary file.

The macho binary expects level file as argument.
Task name suggest that it might be Virtual Machine (VM) crackme.

It looks like the `level` file contains virtual machine bytecode and the vermu is execting it.

After quick analysis we got confirmation - the `100002870` function looks like a typical VM loop.

```asm
[0x100002870]> pd 55
            ;-- func.100002870:
/ (fcn) vm_loop 260
|   vm_loop (int32_t arg1);
|           ; var int32_t op_byte @ rbp-0x19
|           ; var int32_t handler_pointer @ rbp-0x18
|           ; var int32_t vm_bytecode @ rbp-0x10
|           ; var int32_t var_4h @ rbp-0x4
|           ; arg int32_t arg1 @ rdi
|           ; CALL XREF from entry0 @ 0x100002ec2
|           0x100002870      55             push rbp
|           0x100002871      4889e5         mov rbp, rsp
|           0x100002874      4883ec20       sub rsp, 0x20
|           0x100002878      48897df0       mov qword [vm_bytecode], rdi ; arg1
|           0x10000287c      48c745e80000.  mov qword [handler_pointer], 0
|           0x100002884      c645e700       mov byte [op_byte], 0
|           0x100002888      48837df000     cmp qword [vm_bytecode], 0
|       ,=< 0x10000288d      0f850c000000   jne 0x10000289f
|       |   0x100002893      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
|      ,==< 0x10000289a      e9cc000000     jmp 0x10000296b
|      ||   ; CODE XREF from vm_loop @ 0x10000288d
|     ,=`-> 0x10000289f      e900000000     jmp 0x1000028a4
|     ||    ; CODE XREFS from vm_loop @ 0x10000289f, 0x10000295f
|     `-.-> 0x1000028a4      488b45f0       mov rax, qword [vm_bytecode]
|      |:   0x1000028a8      8a8808000800   mov cl, byte [rax + 0x80008]
|      |:   0x1000028ae      80f1ff         xor cl, 0xff               ; 255
|      |:   0x1000028b1      f6c101         test cl, 1                 ; 1
|     ,===< 0x1000028b4      0f8505000000   jne 0x1000028bf
|    ,====< 0x1000028ba      e9a5000000     jmp 0x100002964
|    |||:   ; CODE XREF from vm_loop @ 0x1000028b4
|    |`---> 0x1000028bf      488b45f0       mov rax, qword [vm_bytecode]
|    | |:   0x1000028c3      81b800000800.  cmp dword [rax + 0x80000], 0x80000
|    |,===< 0x1000028cd      0f820c000000   jb 0x1000028df
|    |||:   0x1000028d3      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
|   ,=====< 0x1000028da      e98c000000     jmp 0x10000296b
|   ||||:   ; CODE XREF from vm_loop @ 0x1000028cd
|   ||`---> 0x1000028df      488b45f0       mov rax, qword [vm_bytecode]
|   || |:   0x1000028e3      488b4df0       mov rcx, qword [vm_bytecode]
|   || |:   0x1000028e7      8b9100000800   mov edx, dword [rcx + 0x80000]
|   || |:   0x1000028ed      89d1           mov ecx, edx
|   || |:   0x1000028ef      408a3408       mov sil, byte [rax + rcx]
|   || |:   0x1000028f3      408875e7       mov byte [op_byte], sil
|   || |:   0x1000028f7      0fb655e7       movzx edx, byte [op_byte]
|   || |:   0x1000028fb      81faff000000   cmp edx, 0xff              ; 255
|   ||,===< 0x100002901      0f8c0c000000   jl 0x100002913
|   ||||:   0x100002907      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
|  ,======< 0x10000290e      e958000000     jmp 0x10000296b
|  |||||:   ; CODE XREF from vm_loop @ 0x100002901
|  |||`---> 0x100002913      488b45f0       mov rax, qword [vm_bytecode]
|  ||| |:   0x100002917      0fb64de7       movzx ecx, byte [op_byte]
|  ||| |:   0x10000291b      89ca           mov edx, ecx
|  ||| |:   0x10000291d      488b84d01000.  mov rax, qword [rax + rdx*8 + 0x80010]
|  ||| |:   0x100002925      488945e8       mov qword [handler_pointer], rax
|  ||| |:   0x100002929      48837de800     cmp qword [handler_pointer], 0
|  |||,===< 0x10000292e      0f850c000000   jne 0x100002940
|  |||||:   0x100002934      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
| ,=======< 0x10000293b      e92b000000     jmp 0x10000296b
| ||||||:   ; CODE XREF from vm_loop @ 0x10000292e
| ||||`---> 0x100002940      488b45e8       mov rax, qword [handler_pointer]
| |||| |:   0x100002944      488b7df0       mov rdi, qword [vm_bytecode]
| |||| |:   0x100002948      ffd0           call rax
| |||| |:   0x10000294a      83f800         cmp eax, 0
| ||||,===< 0x10000294d      0f840c000000   je 0x10000295f
| ||||||:   0x100002953      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
| ========< 0x10000295a      e90c000000     jmp 0x10000296b
| |||||||   ; CODE XREF from vm_loop @ 0x10000294d
| ||||`-`=< 0x10000295f      e940ffffff     jmp 0x1000028a4
| |||| |    ; CODE XREF from vm_loop @ 0x1000028ba
| |||`----> 0x100002964      c745fc000000.  mov dword [var_4h], 0
| |||  |    ; CODE XREFS from vm_loop @ 0x10000289a, 0x1000028da, 0x10000290e, 0x10000293b, 0x10000295a
| ```--`--> 0x10000296b      8b45fc         mov eax, dword [var_4h]
|           0x10000296e      4883c420       add rsp, 0x20
|           0x100002972      5d             pop rbp
\           0x100002973      c3             ret
```

This function fetches bytecode instructions and then calls specific handler for fetched VM opcode in a loop.

Let's check where 0x80010 is also used.
```asm
> pdf @@ func ~ 0x80010
|  ||| |:   0x10000291d      488b84d01000.  mov rax, qword [rax + rdx*8 + 0x80010]
|      |    0x100002b3a      488988100008.  mov qword [rax + 0x80010], rcx
|     ||    0x100002d53      4881c7100008.  add rdi, 0x80010
```

```asm
> pd 50 @ 0x100002b3a
|           0x100002b3a      488988100008.  mov qword [rax + 0x80010], rcx
|           0x100002b41      488b45f0       mov rax, qword [var_10h]
|           0x100002b45      488d0d74eeff.  lea rcx, [sym.func.1000019c0] ; 0x1000019c0
|           0x100002b4c      488988900008.  mov qword [rax + 0x80090], rcx
|           0x100002b53      488b45f0       mov rax, qword [var_10h]
|           0x100002b57      488d0d02efff.  lea rcx, [sym.func.100001a60] ; 0x100001a60
|           0x100002b5e      488988980008.  mov qword [rax + 0x80098], rcx
|           0x100002b65      488b45f0       mov rax, qword [var_10h]
|           0x100002b69      488d0d60efff.  lea rcx, [sym.func.100001ad0] ; 0x100001ad0
|           0x100002b70      488988100108.  mov qword [rax + 0x80110], rcx
|           0x100002b77      488b45f0       mov rax, qword [var_10h]
|           0x100002b7b      488d0d0ef0ff.  lea rcx, [sym.func.100001b90] ; 0x100001b90
|           0x100002b82      488988180108.  mov qword [rax + 0x80118], rcx
|           0x100002b89      488b45f0       mov rax, qword [var_10h]
|           0x100002b8d      488d0dbcf0ff.  lea rcx, [sym.func.100001c50] ; 0x100001c50
|           0x100002b94      488988900108.  mov qword [rax + 0x80190], rcx
|           0x100002b9b      488b45f0       mov rax, qword [var_10h]
|           0x100002b9f      488d0d6af1ff.  lea rcx, [sym.func.100001d10] ; 0x100001d10
|           0x100002ba6      488988980108.  mov qword [rax + 0x80198], rcx
|           0x100002bad      488b45f0       mov rax, qword [var_10h]
|           0x100002bb1      488d0d18f2ff.  lea rcx, [sym.func.100001dd0] ; 0x100001dd0
|           0x100002bb8      488988a00108.  mov qword [rax + 0x801a0], rcx
|           0x100002bbf      488b45f0       mov rax, qword [var_10h]
|           0x100002bc3      488d0d06f3ff.  lea rcx, [sym.func.100001ed0] ; 0x100001ed0
|           0x100002bca      488988a80108.  mov qword [rax + 0x801a8], rcx
|           0x100002bd1      488b45f0       mov rax, qword [var_10h]
|           0x100002bd5      488d0db4f3ff.  lea rcx, [sym.func.100001f90] ; 0x100001f90
|           0x100002bdc      488988b00108.  mov qword [rax + 0x801b0], rcx
|           0x100002be3      488b45f0       mov rax, qword [var_10h]
|           0x100002be7      488d0d62f4ff.  lea rcx, [sym.func.100002050] ; 0x100002050
|           0x100002bee      488988b80108.  mov qword [rax + 0x801b8], rcx
|           0x100002bf5      488b45f0       mov rax, qword [var_10h]
|           0x100002bf9      488d0d10f5ff.  lea rcx, [sym.func.100002110] ; 0x100002110
|           0x100002c00      488988c00108.  mov qword [rax + 0x801c0], rcx
|           0x100002c07      488b45f0       mov rax, qword [var_10h]
|           0x100002c0b      488d0dbef5ff.  lea rcx, [sym.func.1000021d0] ; 0x1000021d0
|           0x100002c12      488988c80108.  mov qword [rax + 0x801c8], rcx
|           0x100002c19      488b45f0       mov rax, qword [var_10h]
|           0x100002c1d      488d0d6cf6ff.  lea rcx, [sym.func.100002290] ; 0x100002290
|           0x100002c24      488988d00108.  mov qword [rax + 0x801d0], rcx
|           0x100002c2b      488b45f0       mov rax, qword [var_10h]
|           0x100002c2f      488d0dfaf6ff.  lea rcx, [sym.func.100002330] ; 0x100002330
|           0x100002c36      488988100208.  mov qword [rax + 0x80210], rcx
|           0x100002c3d      488b45f0       mov rax, qword [var_10h]
|           0x100002c41      488d0d88f7ff.  lea rcx, [sym.func.1000023d0] ; 0x1000023d0
|           0x100002c48      488988180208.  mov qword [rax + 0x80218], rcx
|           0x100002c4f      488b45f0       mov rax, qword [var_10h]
|           0x100002c53      488d0de6f7ff.  lea rcx, [sym.func.100002440] ; 0x100002440
|           0x100002c5a      488988200208.  mov qword [rax + 0x80220], rcx
|           0x100002c61      488b45f0       mov rax, qword [var_10h]

> s 0x100002b3a; sf.
[0x100002b10]> 
```

The function `0x100002b10` initializes pointers of the bytecode handlers.
From the VM loop we know that the first byte of bytecode is used as index of handlers array.

Thus, we can make a following table:


 Opcode | Handler address
--- | ---
 0x00   | `0x100001980`
 0x10   | `0x1000019C0`
 0x11   | `0x100001A60`
 0x20   | `0x100001AD0`
 0x21   | `0x100001B90`
 0x30   | `0x100001C50`
 0x31   | `0x100001D10`
 0x32   | `0x100001DD0`
 0x33   | `0x100001ED0`
 0x34   | `0x100001F90`
 0x35   | `0x100002050`
 0x36   | `0x100002110`
 0x37   | `0x1000021D0`
 0x38   | `0x100002290`
 0x40   | `0x100002330`
 0x41   | `0x1000023D0`
 0x42   | `0x100002440`
 0x43   | `0x1000025C0`
 0x44   | `0x100002680`
 0x45   | `0x100002500`
 0x50   | `0x100002740`
 0x60   | `0x100002820`


There are only 22 handlers, we can analyze them manually.

Let's check handler for the 0x00 instruction.

```asm
> pd 15 @ 0x100001980
/ (fcn) sym.func.100001980 62
|   sym.func.100001980 (uint32_t arg1);
|           ; var uint32_t var_10h @ rbp-0x10
|           ; var int32_t var_4h @ rbp-0x4
|           ; arg uint32_t arg1 @ rdi
|           ; DATA XREF from sym.func.100002b10 @ 0x100002b33
|           0x100001980      55             push rbp
|           0x100001981      4889e5         mov rbp, rsp
|           0x100001984      48897df0       mov qword [var_10h], rdi   ; arg1
|           0x100001988      48837df000     cmp qword [var_10h], 0
|       ,=< 0x10000198d      0f850c000000   jne 0x10000199f
|       |   0x100001993      c745fcffffff.  mov dword [var_4h], 0xffffffff ; -1
|      ,==< 0x10000199a      e91a000000     jmp 0x1000019b9
|      ||   ; CODE XREF from sym.func.100001980 @ 0x10000198d
|      |`-> 0x10000199f      488b45f0       mov rax, qword [var_10h]
|      |    0x1000019a3      8b8800000800   mov ecx, dword [rax + 0x80000]
|      |    0x1000019a9      83c101         add ecx, 1
|      |    0x1000019ac      898800000800   mov dword [rax + 0x80000], ecx
|      |    0x1000019b2      c745fc000000.  mov dword [var_4h], 0
|      |    ; CODE XREF from sym.func.100001980 @ 0x10000199a
|      `--> 0x1000019b9      8b45fc         mov eax, dword [var_4h]
|           0x1000019bc      5d             pop rbp
\           0x1000019bd      c3             ret
```

As we can see this instruction does not do anything just increases the `VM_IP` (which stored at ptr + 0x80000).
So 0x00 is NOP instruction.

After analyzing some of handlers I come up with this disassemler code in python:

```python
import sys
import struct

def print_opcodes(addr, data, size, mnemonics = None):

    string1 = ''
    
    for i in range(size):
        string1 = string1 + '{0:02X} '.format(data[addr + i])
    
    line = '{0:08X}:  {1:s}'.format(addr, string1)
    
    if mnemonics is None:
        print(line.ljust(50 , ' '))
    else:
        print(line.ljust(50 , ' ') + mnemonics)

    return    
    
def main():
    
    if len(sys.argv) < 2:
        print("Usage: {0:s} file".format(sys.argv[0]))
        return

    f = open(sys.argv[1], "rb")
    data = f.read()
    f.close()
    
    current_ptr = 0
    STACK = 0x0
    while True:
        
        opcode = struct.unpack_from('<B', data, current_ptr)[0]
       
        if opcode == 0x00:
          
            decoded = 'NOP'
            print_opcodes(current_ptr, data, 0x1)
            current_ptr += 0x1
            
        elif opcode == 0x10:
            param1 = struct.unpack_from('>L', data, current_ptr + 1)[0]
            
            STACK = param1
            decoded = 'PUSH STACK 0x{0:04X}'.format(param1)
            print_opcodes(current_ptr, data, 0x5, decoded)
            current_ptr += 0x5

        elif opcode == 0x11:
           
            decoded = 'POP STACK'
            print_opcodes(current_ptr, data, 0x1)
            current_ptr += 0x1

            
        elif opcode == 0x20:
          
            decoded = 'MOV [STACK1], STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1
        elif opcode == 0x21:
          
            decoded = 'PUSH VALUE AT [STACK1]'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1 
            
        elif opcode == 0x30:
          
            decoded = 'STACK1 = STACK1 + STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1
        elif opcode == 0x31:
          
            decoded = 'STACK1 = STACK1 ^ STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1 
            
        elif opcode == 0x32:
          
            decoded = 'STACK1 = STACK1 vs STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1             
        elif opcode == 0x33:
          
            decoded = 'STACK1 = STACK1 * STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1  
        elif opcode == 0x34:
          
            decoded = 'STACK1 = STACK1 & STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1 
        elif opcode == 0x35:
          
            decoded = 'STACK1 = STACK1 | STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1
        elif opcode == 0x36:
          
            decoded = 'STACK1 = STACK1 SHL STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1     
        elif opcode == 0x37:
          
            decoded = 'STACK1 = STACK1 SHR STACK2'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1  
        elif opcode == 0x38:
          
            decoded = 'STACK1 = STACK1 ^ 0xFFFFFFFF'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1

        elif opcode == 0x40:
          
            decoded = 'CALL 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            
            current_ptr += 0x1
                
        elif opcode == 0x41:
          
            decoded = 'JMP 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            
            current_ptr = STACK
            
        elif opcode == 0x42:
          
            decoded = 'CONDITIONAL JMP 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            
            
            if current_ptr == 0x4EC:
                current_ptr = STACK
            else:
                current_ptr += 0x1
            
        elif opcode == 0x43:
          
            decoded = 'UNK1 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1   
        elif opcode == 0x44:
          
            decoded = 'UNK2 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1
        elif opcode == 0x45:
          
            decoded = 'CONDITIONAL JMP 0x{0:04X}'.format(STACK)
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1

        elif opcode == 0x50:
            
            if STACK == 0x01:
               decoded = 'CALL PRINT'
            else:
               decoded = 'CALL INPUT'
               
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1
            
        elif opcode == 0x60:
          
            decoded = 'EXIT'
            print_opcodes(current_ptr, data, 0x1, decoded)
            current_ptr += 0x1            
            
        else:
            print_opcodes(current_ptr, data, 0x1)
            break
        
    
if __name__=='__main__':
    main()
```

Not all handlers are analyzed properly, but it's good enough to produce readable result.

Here is how disassemled version of level1 VM looks like:
```
00000000:  10 00 00 10 08                         PUSH STACK 0x1008
00000005:  10 00 00 00 20                         PUSH STACK 0x0020
0000000A:  10 00 00 00 00                         PUSH STACK 0x0000
0000000F:  50                                     CALL INPUT
00000010:  10 00 00 00 56                         PUSH STACK 0x0056
00000015:  41                                     JMP 0x0056
00000056:  10 00 00 00 01                         PUSH STACK 0x0001
0000005B:  10 00 00 10 04                         PUSH STACK 0x1004
00000060:  20                                     MOV [STACK1], STACK2
00000061:  10 00 00 10 08                         PUSH STACK 0x1008
00000066:  10 00 00 10 00                         PUSH STACK 0x1000
0000006B:  21                                     PUSH VALUE AT [STACK1]
0000006C:  10 00 00 00 04                         PUSH STACK 0x0004
00000071:  33                                     STACK1 = STACK1 * STACK2
00000072:  30                                     STACK1 = STACK1 + STACK2
00000073:  21                                     PUSH VALUE AT [STACK1]
00000074:  10 00 00 00 16                         PUSH STACK 0x0016
00000079:  10 00 00 10 00                         PUSH STACK 0x1000
0000007E:  21                                     PUSH VALUE AT [STACK1]
0000007F:  10 00 00 00 04                         PUSH STACK 0x0004
00000084:  33                                     STACK1 = STACK1 * STACK2
00000085:  30                                     STACK1 = STACK1 + STACK2
00000086:  21                                     PUSH VALUE AT [STACK1]
00000087:  38                                     STACK1 = STACK1 ^ 0xFFFFFFFF
00000088:  31                                     STACK1 = STACK1 ^ STACK2
00000089:  10 00 00 00 36                         PUSH STACK 0x0036
0000008E:  10 00 00 10 00                         PUSH STACK 0x1000
00000093:  21                                     PUSH VALUE AT [STACK1]
00000094:  10 00 00 00 04                         PUSH STACK 0x0004
00000099:  33                                     STACK1 = STACK1 * STACK2
0000009A:  30                                     STACK1 = STACK1 + STACK2
0000009B:  21                                     PUSH VALUE AT [STACK1]
0000009C:  32                                     STACK1 = STACK1 vs STACK2
0000009D:  10 00 00 00 B4                         PUSH STACK 0x00B4
000000A2:  42                                     CONDITIONAL JMP 0x00B4
000000A3:  10 00 00 00 00                         PUSH STACK 0x0000
000000A8:  10 00 00 10 04                         PUSH STACK 0x1004
000000AD:  20                                     MOV [STACK1], STACK2
000000AE:  10 00 00 00 C6                         PUSH STACK 0x00C6
000000B3:  41                                     JMP 0x00C6
000000C6:  10 00 00 10 00                         PUSH STACK 0x1000
000000CB:  21                                     PUSH VALUE AT [STACK1]
000000CC:  10 00 00 00 01                         PUSH STACK 0x0001
000000D1:  30                                     STACK1 = STACK1 + STACK2
000000D2:  10 00 00 10 00                         PUSH STACK 0x1000
000000D7:  20                                     MOV [STACK1], STACK2
000000D8:  10 00 00 00 08                         PUSH STACK 0x0008
000000DD:  10 00 00 10 00                         PUSH STACK 0x1000
000000E2:  21                                     PUSH VALUE AT [STACK1]
000000E3:  32                                     STACK1 = STACK1 vs STACK2
000000E4:  10 00 00 00 61                         PUSH STACK 0x0061
000000E9:  45                                     CONDITIONAL JMP 0x0061
000000EA:  10 00 00 10 04                         PUSH STACK 0x1004
000000EF:  21                                     PUSH VALUE AT [STACK1]
000000F0:  10 00 00 00 01                         PUSH STACK 0x0001
000000F5:  32                                     STACK1 = STACK1 vs STACK2
000000F6:  10 00 00 01 0D                         PUSH STACK 0x010D
000000FB:  42                                     CONDITIONAL JMP 0x010D
000000FC:  10 00 00 01 24                         PUSH STACK 0x0124
00000101:  10 00 00 00 08                         PUSH STACK 0x0008
00000106:  10 00 00 00 01                         PUSH STACK 0x0001
0000010B:  50                                     CALL PRINT
0000010C:  60                                     EXIT
0000010D:  10 00 00 01 1E                         PUSH STACK 0x011E
00000112:  10 00 00 00 06                         PUSH STACK 0x0006
00000117:  10 00 00 00 01                         PUSH STACK 0x0001
0000011C:  50                                     CALL PRINT
0000011D:  60                                     EXIT
```

The most important instructions are:
```asm
00000074:  10 00 00 00 16                         PUSH STACK 0x0016
...
00000087:  38                                     STACK1 = STACK1 ^ 0xFFFFFFFF
00000088:  31                                     STACK1 = STACK1 ^ STACK2
...
00000089:  10 00 00 00 36                         PUSH STACK 0x0036
...

```
`0x0016` and `0x0036` are not constants, but offsets.

So VM takes user's input, and compares it with value, which is decrypted using XOR.
To decrypt the value we just need to XOR bytes at `0x0016` and `0x0036` to each other, then XOR with 0xFF.

I printed offsets:
```asm
[0x00000000]> px32 @ 0x16
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000016  bce6 b80a baad 1bab c5dd 1214 b2c1 1b74  ...............t
0x00000026  7fc5 2197 6555 1298 9315 df80 1529 7c7d  ..!.eU.......)|}
[0x00000000]> px32 @ 0x36
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000036  312b 249a 2b29 d567 0d7d 80d8 124e 91be  1+$.+).g.}...N..
0x00000046  e865 a758 efd8 b252 18de 4314 cbed aaff  .e.X...R..C.....
```

Then used the [CyberChief](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'312b249a2b29d5670d7d80d8124e91bee865a758efd8b25218de4314cbedaaff'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'FF'%7D,'Standard',false)&input=YmNlNmI4MGFiYWFkMWJhYmM1ZGQxMjE0YjJjMTFiNzQ3ZmM1MjE5NzY1NTUxMjk4OTMxNWRmODAxNTI5N2M3ZA)

The flag is: `r2con{137_m3_pu5h_y0ur_5t4ck!;)}`

# vermu 2

This is exactly similar task.
The binary is not modified at all, which means we can use our python VM disassemler.

```asm
00000000:  10 00 00 01 05                         PUSH STACK 0x0105
00000005:  41                                     JMP 0x0105
00000105:  10 00 00 08 AF                         PUSH STACK 0x08AF
0000010A:  10 00 00 00 14                         PUSH STACK 0x0014
0000010F:  10 00 00 00 01                         PUSH STACK 0x0001
00000114:  50                                     CALL PRINT
00000115:  10 00 00 02 1A                         PUSH STACK 0x021A
0000011A:  41                                     JMP 0x021A
0000021A:  10 00 00 10 0C                         PUSH STACK 0x100C
0000021F:  10 00 00 00 20                         PUSH STACK 0x0020
00000224:  10 00 00 00 00                         PUSH STACK 0x0000
00000229:  50                                     CALL INPUT
0000022A:  10 00 00 03 2F                         PUSH STACK 0x032F
0000022F:  41                                     JMP 0x032F
0000032F:  10 00 00 00 01                         PUSH STACK 0x0001
00000334:  10 00 00 10 08                         PUSH STACK 0x1008
00000339:  20                                     MOV [STACK1], STACK2
0000033A:  10 00 00 04 44                         PUSH STACK 0x0444
0000033F:  41                                     JMP 0x0444
00000444:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000449:  10 00 00 10 00                         PUSH STACK 0x1000
0000044E:  21                                     PUSH VALUE AT [STACK1]
0000044F:  10 00 00 00 04                         PUSH STACK 0x0004
00000454:  33                                     STACK1 = STACK1 * STACK2
00000455:  30                                     STACK1 = STACK1 + STACK2
00000456:  21                                     PUSH VALUE AT [STACK1]
00000457:  10 00 00 08 D1                         PUSH STACK 0x08D1
0000045C:  21                                     PUSH VALUE AT [STACK1]
0000045D:  31                                     STACK1 = STACK1 ^ STACK2
0000045E:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000463:  10 00 00 10 00                         PUSH STACK 0x1000
00000468:  21                                     PUSH VALUE AT [STACK1]
00000469:  10 00 00 00 04                         PUSH STACK 0x0004
0000046E:  33                                     STACK1 = STACK1 * STACK2
0000046F:  30                                     STACK1 = STACK1 + STACK2
00000470:  20                                     MOV [STACK1], STACK2
00000471:  10 00 00 10 00                         PUSH STACK 0x1000
00000476:  21                                     PUSH VALUE AT [STACK1]
00000477:  10 00 00 00 01                         PUSH STACK 0x0001
0000047C:  30                                     STACK1 = STACK1 + STACK2
0000047D:  10 00 00 10 00                         PUSH STACK 0x1000
00000482:  20                                     MOV [STACK1], STACK2
00000483:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000488:  10 00 00 10 00                         PUSH STACK 0x1000
0000048D:  21                                     PUSH VALUE AT [STACK1]
0000048E:  10 00 00 00 04                         PUSH STACK 0x0004
00000493:  33                                     STACK1 = STACK1 * STACK2
00000494:  30                                     STACK1 = STACK1 + STACK2
00000495:  10 00 00 05 3E                         PUSH STACK 0x053E
0000049A:  32                                     STACK1 = STACK1 vs STACK2
0000049B:  10 00 00 04 44                         PUSH STACK 0x0444
000004A0:  44                                     UNK2 0x0444
000004A1:  10 00 00 04 AC                         PUSH STACK 0x04AC
000004A6:  41                                     JMP 0x04AC
```

In this VM XOR loop is used between bytes at two offset: `0x08D1` and `0x04AC`
However this time the VM decrypts code, not the flag.

I performed this XOR operation manually, after that I got the following code of full VM:

```asm
00000000:  10 00 00 01 05                         PUSH STACK 0x0105
00000005:  41                                     JMP 0x0105
00000105:  10 00 00 08 AF                         PUSH STACK 0x08AF
0000010A:  10 00 00 00 14                         PUSH STACK 0x0014
0000010F:  10 00 00 00 01                         PUSH STACK 0x0001
00000114:  50                                     CALL PRINT
00000115:  10 00 00 02 1A                         PUSH STACK 0x021A
0000011A:  41                                     JMP 0x021A
0000021A:  10 00 00 10 0C                         PUSH STACK 0x100C
0000021F:  10 00 00 00 20                         PUSH STACK 0x0020
00000224:  10 00 00 00 00                         PUSH STACK 0x0000
00000229:  50                                     CALL INPUT
0000022A:  10 00 00 03 2F                         PUSH STACK 0x032F
0000022F:  41                                     JMP 0x032F
0000032F:  10 00 00 00 01                         PUSH STACK 0x0001
00000334:  10 00 00 10 08                         PUSH STACK 0x1008
00000339:  20                                     MOV [STACK1], STACK2
0000033A:  10 00 00 04 44                         PUSH STACK 0x0444
0000033F:  41                                     JMP 0x0444
00000444:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000449:  10 00 00 10 00                         PUSH STACK 0x1000
0000044E:  21                                     PUSH VALUE AT [STACK1]
0000044F:  10 00 00 00 04                         PUSH STACK 0x0004
00000454:  33                                     STACK1 = STACK1 * STACK2
00000455:  30                                     STACK1 = STACK1 + STACK2
00000456:  21                                     PUSH VALUE AT [STACK1]
00000457:  10 00 00 08 D1                         PUSH STACK 0x08D1
0000045C:  21                                     PUSH VALUE AT [STACK1]
0000045D:  31                                     STACK1 = STACK1 ^ STACK2
0000045E:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000463:  10 00 00 10 00                         PUSH STACK 0x1000
00000468:  21                                     PUSH VALUE AT [STACK1]
00000469:  10 00 00 00 04                         PUSH STACK 0x0004
0000046E:  33                                     STACK1 = STACK1 * STACK2
0000046F:  30                                     STACK1 = STACK1 + STACK2
00000470:  20                                     MOV [STACK1], STACK2
00000471:  10 00 00 10 00                         PUSH STACK 0x1000
00000476:  21                                     PUSH VALUE AT [STACK1]
00000477:  10 00 00 00 01                         PUSH STACK 0x0001
0000047C:  30                                     STACK1 = STACK1 + STACK2
0000047D:  10 00 00 10 00                         PUSH STACK 0x1000
00000482:  20                                     MOV [STACK1], STACK2
00000483:  10 00 00 04 AC                         PUSH STACK 0x04AC
00000488:  10 00 00 10 00                         PUSH STACK 0x1000
0000048D:  21                                     PUSH VALUE AT [STACK1]
0000048E:  10 00 00 00 04                         PUSH STACK 0x0004
00000493:  33                                     STACK1 = STACK1 * STACK2
00000494:  30                                     STACK1 = STACK1 + STACK2
00000495:  10 00 00 05 3E                         PUSH STACK 0x053E
0000049A:  32                                     STACK1 = STACK1 vs STACK2
0000049B:  10 00 00 04 44                         PUSH STACK 0x0444
000004A0:  44                                     UNK2 0x0444
000004A1:  10 00 00 04 AC                         PUSH STACK 0x04AC
000004A6:  41                                     JMP 0x04AC
000004AC:  10 00 00 10 0C                         PUSH STACK 0x100C
000004B1:  10 00 00 10 04                         PUSH STACK 0x1004
000004B6:  21                                     PUSH VALUE AT [STACK1]
000004B7:  10 00 00 00 04                         PUSH STACK 0x0004
000004BC:  33                                     STACK1 = STACK1 * STACK2
000004BD:  30                                     STACK1 = STACK1 + STACK2
000004BE:  21                                     PUSH VALUE AT [STACK1]
000004BF:  10 00 00 04 FE                         PUSH STACK 0x04FE
000004C4:  10 00 00 10 04                         PUSH STACK 0x1004
000004C9:  21                                     PUSH VALUE AT [STACK1]
000004CA:  10 00 00 00 04                         PUSH STACK 0x0004
000004CF:  33                                     STACK1 = STACK1 * STACK2
000004D0:  30                                     STACK1 = STACK1 + STACK2
000004D1:  21                                     PUSH VALUE AT [STACK1]
000004D2:  31                                     STACK1 = STACK1 ^ STACK2
000004D3:  10 00 00 05 1E                         PUSH STACK 0x051E
000004D8:  10 00 00 10 04                         PUSH STACK 0x1004
000004DD:  21                                     PUSH VALUE AT [STACK1]
000004DE:  10 00 00 00 04                         PUSH STACK 0x0004
000004E3:  33                                     STACK1 = STACK1 * STACK2
000004E4:  30                                     STACK1 = STACK1 + STACK2
000004E5:  21                                     PUSH VALUE AT [STACK1]
000004E6:  32                                     STACK1 = STACK1 vs STACK2
000004E7:  10 00 00 06 41                         PUSH STACK 0x0641
000004EC:  42                                     CONDITIONAL JMP 0x0641
00000641:  10 00 00 00 01                         PUSH STACK 0x0001
00000646:  10 00 00 10 08                         PUSH STACK 0x1008
0000064B:  21                                     PUSH VALUE AT [STACK1]
0000064C:  34                                     STACK1 = STACK1 & STACK2
0000064D:  10 00 00 10 08                         PUSH STACK 0x1008
00000652:  20                                     MOV [STACK1], STACK2
00000653:  10 00 00 07 58                         PUSH STACK 0x0758
00000658:  41                                     JMP 0x0758
00000758:  10 00 00 10 04                         PUSH STACK 0x1004
0000075D:  21                                     PUSH VALUE AT [STACK1]
0000075E:  10 00 00 00 01                         PUSH STACK 0x0001
00000763:  30                                     STACK1 = STACK1 + STACK2
00000764:  10 00 00 10 04                         PUSH STACK 0x1004
00000769:  20                                     MOV [STACK1], STACK2
0000076A:  10 00 00 00 08                         PUSH STACK 0x0008
0000076F:  10 00 00 10 04                         PUSH STACK 0x1004
00000774:  21                                     PUSH VALUE AT [STACK1]
00000775:  32                                     STACK1 = STACK1 vs STACK2
00000776:  10 00 00 04 AC                         PUSH STACK 0x04AC
0000077B:  45                                     CONDITIONAL JMP 0x04AC
0000077C:  10 00 00 10 08                         PUSH STACK 0x1008
00000781:  21                                     PUSH VALUE AT [STACK1]
00000782:  10 00 00 00 01                         PUSH STACK 0x0001
00000787:  32                                     STACK1 = STACK1 vs STACK2
00000788:  10 00 00 08 9E                         PUSH STACK 0x089E
0000078D:  42                                     CONDITIONAL JMP 0x089E
0000078E:  10 00 00 08 C9                         PUSH STACK 0x08C9
00000793:  10 00 00 00 08                         PUSH STACK 0x0008
00000798:  10 00 00 00 01                         PUSH STACK 0x0001
0000079D:  50                                     CALL PRINT
0000079E:  60                                     EXIT
0000079F:  D1                                     
```

Again we can spot the XOR operation inside decrypted code between `0x04FE` and `0x051E`

Let's dump these values again (from the manually patched version):
```asm
[0x00000000]> px32 @ 0x04FE
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000004fe  cce1 a20a bada b1ba 7cdd 120a b21c 1b57  ........|......W
0x0000050e  7fc5 2197 6555 0248 9315 df80 1529 7c7d  ..!.eU.H.....)|}
[0x00000000]> px32 @ 0x051E
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000051e  bed3 c165 d4a1 d2d6 48bc 7c55 d67d 4424  ...e....H.|U.}D$
0x0000052e  0bf1 42fc 3a37 312e fc67 badf 7f44 0c00  ..B.:71..g...D..
```

Then let's use the [CyberChief](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'bed3c165d4a1d2d648bc7c55d67d44240bf142fc3a37312efc67badf7f440c00'%7D,'Standard',false)&input=Y2NlMWEyMGFiYWRhYjFiYTdjZGQxMjBhYjIxYzFiNTc3ZmM1MjE5NzY1NTUwMjQ4OTMxNWRmODAxNTI5N2M3ZA)

The flag is: `r2con{cl4an_da_st4ck_b3fore_jmp}`
