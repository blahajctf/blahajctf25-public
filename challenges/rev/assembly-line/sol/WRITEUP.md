autorev to dump constraints that each binary encodes

the binaries all follow this format
`[BOOLEAN EXPRESSION] AND DUMP`

the boolean expression is the constraint to dump
autorev involves solving for the opcode function offsets, then going off the switch case ordering to figure out what the unique order is for each bin
also theres an XOR key to dump for the bytecode

after you dump the constraints, just toss into z3 to get pastebin link
pastebin.com/0310tMsz <-- flag is here