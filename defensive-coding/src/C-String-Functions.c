#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void
log_string(const char *s)
{
  puts(s);
}

//+ C String-Functions-format
void log_format(const char *format, ...) __attribute__((format(printf, 1, 2)));

void
log_format(const char *format, ...)
{
  char buf[1000];
  va_list ap;
  va_start(ap, format);
  vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);
  log_string(buf);
}
//-

int
main(void)
{
  {
    int numerator = 3, denominator = 4;
    //+ C String-Functions-snprintf
    char fraction[30];
    snprintf(fraction, sizeof(fraction), "%d/%d", numerator, denominator);
    //-
    puts(fraction);
  }
  log_format("%s %x", "foo", 0xba4);
  {
    const char *const data = "this message is quite long";
    //+ C String-Functions-strncpy
    char buf[10];
    strncpy(buf, data, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    //-
    assert(strlen(buf) == 9);
    assert(strncmp(buf, data, 9) == 0);
  }
}