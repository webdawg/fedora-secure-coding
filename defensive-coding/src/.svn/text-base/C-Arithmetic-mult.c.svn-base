void report_overflow(void);

//+ C Arithmetic-mult
unsigned
mul(unsigned a, unsigned b)
{
  if (b && a > ((unsigned)-1) / b) {
    report_overflow();
  }
  return a * b;
}
//-
