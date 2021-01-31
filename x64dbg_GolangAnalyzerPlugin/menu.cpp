#include "menu.h"

static bool line_enabled = false;


bool get_line_enabled()
{
    return line_enabled;
}
void set_line_enabled(bool value)
{
    line_enabled = value;
}