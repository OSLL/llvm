#include <stdio.h>
#include <udis86.h>

int main()
{
    ud_t ud_obj;
    FILE *p = NULL;
    FILE *s = NULL;
//    p = fopen("test", "rb");
//    s = fopen("output", "w");
    if (p != NULL && s != NULL)
    {
        fprintf(stdout, "fopen(): OK\n");
    }
    else fprintf(stdout, "fopen(): ERROR\n");

    ud_init(&ud_obj);
    ud_set_input_file(&ud_obj, stdin);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_ATT);

    while (ud_disassemble(&ud_obj))
    {
        fprintf(stdout, "\t%s\n", ud_insn_asm(&ud_obj));
    }
    fclose(p);
    fclose(s);
    return 0;
}
