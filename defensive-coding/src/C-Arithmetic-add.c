//+ C Arithmetic-add
void report_overflow(void);

int
add(int a, int b)
{
  int result = a + b;
  if (a < 0 || b < 0) {
    return -1;
  }
  // The compiler can optimize away the following if statement.
  if (result < 0) {
    report_overflow();
  }
  return result;
}
//-

//+ C Arithmetic-add_unsigned
void report_overflow(void);

unsigned
add_unsigned(unsigned a, unsigned b)
{
  unsigned sum = a + b;
  if (sum < a) { // or sum < b
    report_overflow();
  }
  return sum;
}
//-
