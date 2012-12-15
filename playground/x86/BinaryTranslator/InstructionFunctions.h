#ifndef INSTRUCTIONFUNCTIONS_H
#define INSTRUCTIONFUNCTIONS_H

#include "CPUstate.h"

// mov
void Mov (CPUstate * env, int src, int dst);

// movl
void Movl (CPUstate * env, int src, int dst);

// add
void Add (CPUstate * env, int src, int dst);

#endif // INSTRUCTIONFUNCTIONS_H
