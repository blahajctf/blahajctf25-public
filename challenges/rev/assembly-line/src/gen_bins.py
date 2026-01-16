# idgaf
import random
import subprocess

f = open("constraints.txt")
constraints = f.read().split("\n")
f.close()
for n, constraint in enumerate(constraints):
    opcodes = [_ for _ in range(14)] 
    random.shuffle(opcodes)
    """
    OP_PUSH_CONST = {opcodes[0]}
    OP_ADD        = {opcodes[1]}
    OP_SUB        = {opcodes[2]}
    OP_MUL        = {opcodes[3]}
    OP_DIV        = {opcodes[4]}
    OP_AND        = {opcodes[5]}
    OP_OR         = {opcodes[6]}
    OP_XOR        = {opcodes[7]}
    OP_NOT        = {opcodes[8]}
    OP_DUP        = {opcodes[9]}
    OP_EQ         = {opcodes[10]}
    OP_NEQ        = {opcodes[11]}
    OP_LE         = {opcodes[12]}
    OP_GE         = {opcodes[13]}
    """
    opcode_map = {
        "PUSH": opcodes[0],
        "ADD":  opcodes[1],
        "SUB":  opcodes[2],
        "MUL":  opcodes[3],
        "DIV":  opcodes[4],
        "AND":  opcodes[5],
        "OR":   opcodes[6],
        "XOR":  opcodes[7],
        "NOT":  opcodes[8],
        "DUP":  opcodes[9],  
        "EQ":   opcodes[10],
        "NEQ":  opcodes[11],
        "LE":   opcodes[12],
        "GE":   opcodes[13],
        "DUMP": 0xff
    }
    bytecode = []
    for token in constraint.split(" "):
        if token.isdigit():
            val = int(token)
            bytecode.append(val)
        elif token[:2] == "0x":
            val = int(token, 16)
            val = list(val.to_bytes(4, "big"))
            bytecode += val
        else:
            bytecode.append(opcode_map[token])
    
    print(n, constraint, ','.join([hex(c) for c in bytecode]))
    xor_key = random.randint(0, 255)
    bytecode = [c ^ xor_key for c in bytecode]
    
    source = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define STACK_SIZE 256
#define XOR_KEY {xor_key}
#define INPUT_TERMINATOR 0x69
#define OUTPUT_TERMINATOR 0x69


unsigned char bytecode[] = {{
    {','.join([hex(c) for c in bytecode])}
}};
const unsigned int bytecode_len = sizeof(bytecode);

//================================================================//
//                      OPCODE DEFINITIONS                        //
//================================================================//
// we will shuffle these
typedef enum {{
    OP_PUSH_CONST = {opcodes[0]},
    OP_ADD        = {opcodes[1]},
    OP_SUB        = {opcodes[2]},
    OP_MUL        = {opcodes[3]},
    OP_DIV        = {opcodes[4]},
    OP_AND        = {opcodes[5]},
    OP_OR         = {opcodes[6]},
    OP_XOR        = {opcodes[7]},
    OP_NOT        = {opcodes[8]},
    OP_DUP        = {opcodes[9]},
    OP_EQ         = {opcodes[10]},
    OP_NEQ        = {opcodes[11]},
    OP_LE         = {opcodes[12]},
    OP_GE         = {opcodes[13]},
    OP_DUMP       = 0xFF
}} Opcodes;

typedef struct {{
    unsigned int stack[STACK_SIZE];
    int sp; 
    unsigned char* ip; 
}} VM;

void init_vm(VM* vm) {{
    vm->sp = 0;
    vm->ip = bytecode;
}}

void push(VM* vm, int value) {{
    if (vm->sp >= STACK_SIZE) {{
        fprintf(stderr, "Error: Stack overflow\\n");
        exit(EXIT_FAILURE);
    }}
    vm->stack[vm->sp++] = value;
}}

int pop(VM* vm) {{
    if (vm->sp <= 0) {{
        fprintf(stderr, "Error: Stack underflow\\n");
        exit(EXIT_FAILURE);
    }}
    return vm->stack[--vm->sp];
}}

void read_input_into_stack(VM* vm) {{
    char buffer[16];
    unsigned int buffer_idx = 0;
    int c;
    while ((c = getchar()) != EOF) {{
        if (c == INPUT_TERMINATOR) {{
            break;
        }}

        if (isdigit(c) || (c == '-' && buffer_idx == 0)) {{
            if (buffer_idx < 15) {{
                buffer[buffer_idx++] = c;
            }}
        }} else if (c == ' ') {{
            if (buffer_idx > 0) {{
                buffer[buffer_idx] = '\\0';
                push(vm, atoi(buffer));
                buffer_idx = 0;
            }}
        }}
    }}
    // Push any final number in the buffer
    if (buffer_idx > 0) {{
        buffer[buffer_idx] = '\\0';
        push(vm, atoi(buffer));
    }}
}}

void run_vm(VM* vm) {{
    int running = 1;
    while (running && (vm->ip < bytecode + bytecode_len)) {{
        // Fetch, decode, and advance instruction pointer
        unsigned char opcode = *(vm->ip) ^ XOR_KEY;
        vm->ip++;

        switch (opcode) {{
            case OP_PUSH_CONST: {{
                unsigned int constant = *(vm->ip) ^ XOR_KEY;
                vm->ip++;
                constant <<= 8;
                constant += *(vm->ip) ^ XOR_KEY;
                vm->ip++;
                constant <<= 8;
                constant += *(vm->ip) ^ XOR_KEY;
                vm->ip++;
                constant <<= 8;
                constant += *(vm->ip) ^ XOR_KEY;
                vm->ip++;
                push(vm, constant);
                break;
            }}
            case OP_ADD: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b + a);
                break;
            }}
            case OP_SUB: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b - a);
                break;
            }}
            case OP_MUL: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b * a);
                break;
            }}
            case OP_DIV: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                if (a == 0) {{
                    fprintf(stderr, "Error: Division by zero\\n");
                    exit(EXIT_FAILURE);
                }}
                push(vm, b / a);
                break;
            }}
            case OP_AND: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b & a);
                break;
            }}
            case OP_OR: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b | a);
                break;
            }}
            case OP_XOR: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b ^ a);
                break;
            }}
            case OP_EQ: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b == a);
                break;
            }}
            case OP_NEQ: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b != a);
                break;
            }}
            case OP_LE: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, a > b);
                break;
            }}
            case OP_GE: {{
                unsigned int a = pop(vm);
                unsigned int b = pop(vm);
                push(vm, b > a);
                break;
            }}
            case OP_NOT: {{
                unsigned int a = pop(vm);
                push(vm, ~a);
                break;
            }}
            case OP_DUMP: {{
                // Print stack from bottom to top
                for (int i = 0; i < vm->sp; i++) {{
                    printf("%d ", vm->stack[i]);
                }}
                printf("%c", OUTPUT_TERMINATOR);
                running = 0;
                break;
            }}
            case OP_DUP: {{
                int target_pos = *(vm->ip) ^ XOR_KEY;
                vm->ip++;
                push(vm, vm->stack[target_pos]);
                break;
            }}
            default: {{
                fprintf(stderr, "Error: Unknown opcode 0x%02X\\n", opcode);
                running = 0;
                break;
            }}
        }}
    }}
}}


int main() {{
    VM vm;
    init_vm(&vm);
    read_input_into_stack(&vm);
    run_vm(&vm);
    return 0;
}}
"""
    tmp = open("tmp.c", "w")
    tmp.write(source)
    tmp.close()
    compile_command = f"gcc -Wall -Wextra -std=c99 -o ./workers/worker_{n} tmp.c"
    subprocess.run(compile_command.split(" "))
    
    
    
    