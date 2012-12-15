#include <iostream>
#include "CPUstate.h"
#include "InstructionFunctions.h"

using namespace std;

int main()
{
    ud_init(&ud_obj);
    ud_set_input_file(&ud_obj, stdin);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_ATT);

    while (ud_disassemble(&ud_obj))
    {
        switch (ud_obj.mnemonic)
        {
        case UD_Imov: Mov(env, &ud_obj);
        case UD_Iadd: Add(env, &ud_obj);
        }
    }

    return 0;
}

