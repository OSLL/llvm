#ifndef INSTRUCTIONFUNCTIONS_H
#define INSTRUCTIONFUNCTIONS_H

#include <udis86.h>
#include "CPUstate.h"

// mov
void Mov (CPUstate * env, const ud_t & inst);

// movl
void Movl (CPUstate * env, const ud_t & inst);

// add
void Add (CPUstate * env, const ud_t & inst);

#endif // INSTRUCTIONFUNCTIONS_H
