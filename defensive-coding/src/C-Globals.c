#include <stddef.h>

//+ C Globals-String_Array
static const char *const string_list[] = {
  "first",
  "second",
  "third",
  NULL
};
//-

// Silence compiler warning
const char *const *
get_string_list()
{
  return string_list;
}
