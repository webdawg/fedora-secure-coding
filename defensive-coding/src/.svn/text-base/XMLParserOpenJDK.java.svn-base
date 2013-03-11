import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

//+ Tasks Serialization-XML-OpenJDK-Imports
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
//-

public final class XMLParserOpenJDK {
    public static void main(String[] args) throws Exception {
        String validationType = args[0];
        File schema = new File(args[1]);
        String file = args[2];
        if (validationType.equals("OpenJDK-XSD-SAX")) {
            validateXSDSAX(schema, file);
        } else if (validationType.equals("OpenJDK-RNG-SAX")) {
            validateSAX(XMLConstants.RELAXNG_NS_URI, schema, file);
        } else if (validationType.equals("OpenJDK-DTD-SAX")) {
            validateSAX(XMLConstants.XML_DTD_NS_URI, schema, file);
        } else if (validationType.equals("OpenJDK-XSD-DOM")) {
            validateXSDDOM(schema, file);
        } else if (validationType.equals("OpenJDK-RNG-DOM")) {
            validateDOM(XMLConstants.W3C_XML_SCHEMA_NS_URI,
                    schema, file, false);
        } else if (validationType.equals("OpenJDK-DTD-DOM")) {
            validateDOM(XMLConstants.XML_DTD_NS_URI, schema, file, false);
        } else if (validationType.equals("OpenJDK-XSD-DOM-Validate")) {
            validateDOM(XMLConstants.W3C_XML_SCHEMA_NS_URI,
                    schema, file, true);
        } else if (validationType.equals("OpenJDK-RNG-DOM-Validate")) {
            validateDOM(XMLConstants.W3C_XML_SCHEMA_NS_URI,
                    schema, file, true);
        } else if (validationType.equals("OpenJDK-DTD-DOM-Validate")) {
            validateDOM(XMLConstants.XML_DTD_NS_URI, schema, file, true);
        } else if (validationType.equals("OpenJDK-SAX")) {
            parseSAX(file, false);
        } else if (validationType.equals("OpenJDK-DOM")) {
            parseDOM(file, false);
        } else if (validationType.equals("OpenJDK-SAX-Validate")) {
            parseSAX(file, true);
        } else if (validationType.equals("OpenJDK-DOM-Validate")) {
            parseDOM(file, true);
        } else {
            throw new Exception("invalid validator: " + validationType);
        }
    }
    
    static
    //+ Tasks Serialization-XML-OpenJDK-NoResourceResolver
    class NoResourceResolver implements LSResourceResolver {
        @Override
        public LSInput resolveResource(String type, String namespaceURI,
                String publicId, String systemId, String baseURI) {
            // Throwing an exception stops validation.
            throw new RuntimeException(String.format(
                    "resolution attempt: type=%s namespace=%s " +
                    "publicId=%s systemId=%s baseURI=%s",
                    type, namespaceURI, publicId, systemId, baseURI));
        }
    }
    //-

    private static void validateXSDSAX( File schemaFile, String file)
            throws Exception {
        FileInputStream inputStream = new FileInputStream(file);
        try {
            //+ Tasks Serialization-XML-OpenJDK_Parse-XMLSchema_SAX
            SchemaFactory factory = SchemaFactory.newInstance(
                    XMLConstants.W3C_XML_SCHEMA_NS_URI);
            
            // This enables restrictions on the schema and document
            // complexity.
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            // This prevents resource resolution by the schema itself.
            // If the schema is trusted and references additional files,
            // this line must be omitted, otherwise loading these files
            // will fail.
            factory.setResourceResolver(new NoResourceResolver());

            Schema schema = factory.newSchema(schemaFile);
            Validator validator = schema.newValidator();

            // This prevents external resource resolution.
            validator.setResourceResolver(new NoResourceResolver());
            
            validator.validate(new SAXSource(new InputSource(inputStream)));
            //-
        } finally {
            inputStream.close();
        }
    }

    /**
     * Same as {@link #validateXSDSAX(File, String)}, but the schema type URI
     * is not hard-coded.
     */
    private static void validateSAX(String uri, File schemaFile, String file) 
            throws Exception {
        FileInputStream inputStream = new FileInputStream(file);
        try {
            SchemaFactory factory = SchemaFactory.newInstance(uri);
            
            // This enables restrictions on the schema and document
            // complexity.
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            // This prevents resource resolution by the schema itself.
            // If the schema is trusted and references additional files,
            // this line must be omitted, otherwise loading these files
            // will fail.
            factory.setResourceResolver(new NoResourceResolver());

            Schema schema = factory.newSchema(schemaFile);
            Validator validator = schema.newValidator();

            // This prevents external resource resolution.
            validator.setResourceResolver(new NoResourceResolver());
            
            validator.validate(new SAXSource(new InputSource(inputStream)));
        } finally {
            inputStream.close();
        }
    }
    
    private static void validateXSDDOM(File schemaFile, String file) throws Exception {
        FileInputStream inputStream = new FileInputStream(file);
        try {
            Document document = parseDOM(file, false);

            //+ Tasks Serialization-XML-OpenJDK_Parse-XMLSchema_DOM
            SchemaFactory factory = SchemaFactory.newInstance(
                    XMLConstants.W3C_XML_SCHEMA_NS_URI);

            // This enables restrictions on schema complexity.
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            // The following line prevents resource resolution
            // by the schema itself.
            factory.setResourceResolver(new NoResourceResolver());

            Schema schema = factory.newSchema(schemaFile);

            Validator validator = schema.newValidator();
            
            // This prevents external resource resolution.
            validator.setResourceResolver(new NoResourceResolver());
            validator.validate(new DOMSource(document));
            //-
        } finally {
            inputStream.close();
        }
    }

    /**
     * Same as {@link #validateXSDDOM(File, String)}, but does not hard-code
     * the schema type URI.
     */
    private static void validateDOM(String uri, File schemaFile, String file,
            boolean validate) throws Exception {
        FileInputStream inputStream = new FileInputStream(file);
        try {
            Document document = parseDOM(file, validate);

            SchemaFactory factory = SchemaFactory.newInstance(uri);

            // This enables restrictions on schema complexity.
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            // The following line prevents resource resolution
            // by the schema itself.
            factory.setResourceResolver(new NoResourceResolver());

            Schema schema = factory.newSchema(schemaFile);

            Validator validator = schema.newValidator();
            // This prevents external resource resolution.
            validator.setResourceResolver(new NoResourceResolver());
            validator.validate(new DOMSource(document));
        } finally {
            inputStream.close();
        }
    }

    static
    //+ Tasks Serialization-XML-OpenJDK-Errors
    class Errors implements ErrorHandler {
        @Override
        public void warning(SAXParseException exception) {
            exception.printStackTrace();
        }
        
        @Override
        public void fatalError(SAXParseException exception) {
            exception.printStackTrace();
        }
        
        @Override
        public void error(SAXParseException exception) {
            exception.printStackTrace();
        }
    }
    //-
    
    static
    //+ Tasks Serialization-XML-OpenJDK-NoEntityResolver
    class NoEntityResolver implements EntityResolver {
        @Override
        public InputSource resolveEntity(String publicId, String systemId)
                throws SAXException, IOException {
            // Throwing an exception stops validation.
            throw new IOException(String.format(
                    "attempt to resolve \"%s\" \"%s\"", publicId, systemId));
        }
    }
    //-

    private static void parseSAX(String file, boolean validate) 
            throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        if (validate) {
            factory.setValidating(true);
        }
        SAXParser parser = factory.newSAXParser();
        FileInputStream in = new FileInputStream(file);
        try {
            XMLReader reader = parser.getXMLReader();
            reader.setEntityResolver(new NoEntityResolver());
            reader.setErrorHandler(new Errors());
            reader.parse(new InputSource(in));
        } finally {
            in.close();
        }
    }

    private static Document parseDOM(String file, boolean validate)
            throws Exception {
        FileInputStream inputStream = new FileInputStream(file);
        try {
            return parseDOMInternal(inputStream);
        } finally {
            inputStream.close();
        }
    }

    private static Document parseDOMInternal(FileInputStream inputStream)
            throws ParserConfigurationException, SAXException, IOException {
        //+ Tasks Serialization-XML-OpenJDK_Parse-DOM
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Impose restrictions on the complexity of the DTD.
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // Turn on validation.
        // This step can be omitted if validation is not desired.
        factory.setValidating(true);

        // Parse the document.
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver(new NoEntityResolver());
        builder.setErrorHandler(new Errors());
        Document document = builder.parse(inputStream);
        //-
        return document;
    }
}
