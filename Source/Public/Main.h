#pragma once

typedef unsigned(_stdcall* ThreadStart) (void*);

#define BEGINSTHREADEX(pas, cbStack, pfnStartAddr, pvParam, fdwCreateFlags, pdwThreadID)\
((HANDLE)_beginthreadex(                \
        (void*)(pas),                   \
        (unsigned)(cbStack),            \
        (ThreadStart)pfnStartAddr,      \
        (void*)(pvParam),               \
        (unsigned)(fdwCreateFlags),     \
        (unsigned)(pdwThreadID)))