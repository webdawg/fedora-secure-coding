#include <QtCore/QBuffer>
#include <QtCore/QByteArray>
#include <QtCore/QFile>
#include <QtXml/QDomDocument>
#include <QtXml/QXmlSimpleReader>

#include <stdio.h>

namespace {
  //+ Tasks Serialization-XML-Qt-NoEntityHandler
  class NoEntityHandler : public QXmlDeclHandler {
  public:
    bool attributeDecl(const QString&, const QString&, const QString&,
		       const QString&, const QString&);
    bool internalEntityDecl(const QString&, const QString&);
    bool externalEntityDecl(const QString&, const QString&,
			    const QString&);
    QString errorString() const;
  };

 bool
  NoEntityHandler::attributeDecl
    (const QString&, const QString&, const QString&, const QString&,
     const QString&)
  {
    return false;
  }

  bool
  NoEntityHandler::internalEntityDecl(const QString&, const QString&)
  {
    return false;
  }

  bool
  NoEntityHandler::externalEntityDecl(const QString&, const QString&, const
				      QString&)
  {
    return false;
  }

  QString
  NoEntityHandler::errorString() const
  {
    return "XML declaration not permitted";
  }
  //-

  //+ Tasks Serialization-XML-Qt-NoEntityReader
  class NoEntityReader : public QXmlSimpleReader {
    NoEntityHandler handler;
  public:
    NoEntityReader();
    void setDeclHandler(QXmlDeclHandler *);
  };

 NoEntityReader::NoEntityReader()
  {
    QXmlSimpleReader::setDeclHandler(&handler);
    setFeature("http://xml.org/sax/features/namespaces", true);
    setFeature("http://xml.org/sax/features/namespace-prefixes", false);
 }

  void
  NoEntityReader::setDeclHandler(QXmlDeclHandler *)
  {
    // Ignore the handler which was passed in.
  }
  //-
}


int
main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s XML-FILE\n", argv[0]);
    return 1;
  }

  QByteArray data;
  {
    QFile f(argv[1]);
    if (!f.open(QIODevice::ReadOnly)) {
      fprintf(stderr, "error: could not open file: %s\n", argv[1]);
      return 1;
    }
    data = f.readAll();
    if (f.error()) {
      fprintf(stderr, "error: could not read file: %s\n", argv[1]);
      return 1;
    }
  }

  //+ Tasks Serialization-XML-Qt-QDomDocument
  NoEntityReader reader;
  QBuffer buffer(&data);
  buffer.open(QIODevice::ReadOnly);
  QXmlInputSource source(&buffer);
  QDomDocument doc;
  QString errorMsg;
  int errorLine;
  int errorColumn;
  bool okay = doc.setContent
    (&source, &reader, &errorMsg, &errorLine, &errorColumn);
  //-
  if (!okay) {
    fprintf(stderr, "%d:%d: %s\n", errorLine, errorColumn,
	    errorMsg.toUtf8().constData());
    return 1;
  }

  data = doc.toByteArray(1);
  if (fwrite(data.constData(), data.size(), 1, stdout) != 1) {
    perror("fwrite");
    return 1;
  }

  return 0;
}
