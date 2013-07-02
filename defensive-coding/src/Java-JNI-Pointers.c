#include <jni.h>

#include <assert.h>

JNIEXPORT jint JNICALL Java_sum
  (JNIEnv *, jclass, jbyteArray, jint, jint);

static jclass arrayIndexOutOfBoundsExceptionClass;

//+ Java JNI-Pointers
JNIEXPORT jint JNICALL Java_sum
  (JNIEnv *jEnv, jclass clazz, jbyteArray buffer, jint offset, jint length)
{
  assert(sizeof(jint) == sizeof(unsigned));
  if (offset < 0 || length < 0) {
    (*jEnv)->ThrowNew(jEnv, arrayIndexOutOfBoundsExceptionClass,
		      "negative offset/length");
    return 0;
  }
  unsigned uoffset = offset;
  unsigned ulength = length;
  // This cannot overflow because of the check above.
  unsigned totallength = uoffset + ulength;
  unsigned actuallength = (*jEnv)->GetArrayLength(jEnv, buffer);
  if (totallength > actuallength) {
    (*jEnv)->ThrowNew(jEnv, arrayIndexOutOfBoundsExceptionClass,
		      "offset + length too large");
    return 0;
  }
  unsigned char *ptr = (*jEnv)->GetPrimitiveArrayCritical(jEnv, buffer, 0);
  if (ptr == NULL) {
    return 0;
  }
  unsigned long long sum = 0;
  for (unsigned char *p = ptr + uoffset, *end = p + ulength; p != end; ++p) {
    sum += *p;
  }
  (*jEnv)->ReleasePrimitiveArrayCritical(jEnv, buffer, ptr, 0);
  return sum;
}
//-
