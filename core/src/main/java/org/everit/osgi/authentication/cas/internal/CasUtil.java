package org.everit.osgi.authentication.cas.internal;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

public class CasUtil {

    private static XMLReader createXmlReader() {
        try {
            XMLReader xmlReader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
            xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
            xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", false);
            xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            return xmlReader;
        } catch (final Exception e) {
            throw new RuntimeException("Unable to create XMLReader", e);
        }
    }

    public static String getTextForElement(final String xmlAsString, final String element) {

        XMLReader reader = CasUtil.createXmlReader();
        StringBuilder builder = new StringBuilder();

        DefaultHandler handler = new DefaultHandler() {

            private boolean foundElement = false;

            @Override
            public void characters(final char[] ch, final int start, final int length) throws SAXException {
                if (foundElement) {
                    builder.append(ch, start, length);
                }
            }

            @Override
            public void endElement(final String uri, final String localName, final String qName) throws SAXException {
                if (localName.equals(element)) {
                    foundElement = false;
                }
            }

            @Override
            public void startElement(final String uri, final String localName, final String qName,
                    final Attributes attributes) throws SAXException {
                if (localName.equals(element)) {
                    foundElement = true;
                }
            }
        };

        reader.setContentHandler(handler);
        reader.setErrorHandler(handler);

        try {
            reader.parse(new InputSource(new StringReader(xmlAsString)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder.toString();
    }

    public static String urlEncode(final String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.displayName());
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
