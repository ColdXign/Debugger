// App.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "ViewPEHeader.h"

int main(void)
{
        wprintf(L"Hello World\n");

        bool bresult = false;

        bresult = load_pe_headers();

        if (true != bresult)
        {
                wprintf(L"PE Header Load is Fail\n");
        }

        return 0;
}