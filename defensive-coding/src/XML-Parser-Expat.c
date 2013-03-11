#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <expat.h>

static void
print_escaped(const char *p, size_t len)
{
  const char *end = p + len;
  while (p < end) {
    unsigned char ch = *p;
    // Technically, we should also match on certain UTF-8 sequences,
    // but this is not implemented here.
    if ((0x01 <= ch && ch <= 0x08)
	|| ch == 0x0B || ch == 0x0C
	|| (0x0E <= ch && ch <= 0x1F)
	|| ch == '"' || ch == '\'' || ch == '<' || ch == '>' || ch == '"'
	|| ch == 0x7F) {
      printf("&#%d;", (int)ch);
    } else {
      putc(ch, stdout);
    }
    ++p;
  }
}

static void
StartElementHandler(void *userData,
		    const XML_Char *name, const XML_Char **attrs)
{
  printf("<%s", name);
  while (*attrs) {
    printf(" %s=\"", *attrs);
    ++attrs;
    print_escaped(*attrs, strlen(*attrs));
    ++attrs;
    putc('"', stdout);
  }
  putc('>', stdout);
}

static void
EndElementHandler(void *userData, const XML_Char *name)
{
  printf("</%s>", name);
}

static void
CharacterDataHandler(void *userData, const XML_Char *s, int len)
{
  print_escaped(s, len);
}

static void
CommentHandler(void *userData, const XML_Char *s)
{
  printf("<!-- %s -->", s);
}

//+ Tasks Serialization-XML-Expat-EntityDeclHandler
// Stop the parser when an entity declaration is encountered.
static void
EntityDeclHandler(void *userData,
		  const XML_Char *entityName, int is_parameter_entity,
		  const XML_Char *value, int value_length,
		  const XML_Char *base, const XML_Char *systemId,
		  const XML_Char *publicId, const XML_Char *notationName)
{
  XML_StopParser((XML_Parser)userData, XML_FALSE);
}
//-

int
main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s XML-FILE\n", argv[0]);
    return 2;
  }

  const char *file = argv[1];
  int fd = open(file, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  //+ Tasks Serialization-XML-Expat-Create
  XML_Parser parser = XML_ParserCreate("UTF-8");
  if (parser == NULL) {
    fprintf(stderr, "XML_ParserCreate failed\n");
    close(fd);
    exit(1);
  }
  // EntityDeclHandler needs a reference to the parser to stop
  // parsing.
  XML_SetUserData(parser, parser);
  // Disable entity processing, to inhibit entity expansion.
  XML_SetEntityDeclHandler(parser, EntityDeclHandler);
  //-

  // Handlers for demonstration purposes.
  XML_SetElementHandler(parser, StartElementHandler, EndElementHandler);
  XML_SetCharacterDataHandler(parser, CharacterDataHandler);
  XML_SetCommentHandler(parser, CommentHandler);


  char buffer[8192];
  ssize_t ret;
  do {
    ret = read(fd, buffer, sizeof(buffer));
    if (ret < 0) {
      perror("read");
      XML_ParserFree(parser);
      close(fd);
      return 1;
    }
    enum XML_Status status = XML_Parse(parser, buffer, ret, ret == 0);
    if (status != XML_STATUS_OK) {
      fprintf(stderr, "%s:%zu:%zu: error: %s\n",
	      file, XML_GetCurrentLineNumber(parser),
	      XML_GetCurrentColumnNumber(parser),
	      XML_ErrorString(XML_GetErrorCode(parser)));
      XML_ParserFree(parser);
      close(fd);
      return 1;
    }
  } while (ret != 0);

  XML_ParserFree(parser);
  close(fd);
  return 0;
}
