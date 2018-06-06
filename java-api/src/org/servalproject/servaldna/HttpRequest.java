package org.servalproject.servaldna;

import org.servalproject.json.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.HttpURLConnection;

public class HttpRequest {
	public String verb;
	public String url;
	private int[] expectedStatusCodes;
	public HttpURLConnection httpConnection;
	public int httpStatusCode;
	public String httpStatusMessage;
	public ContentType contentType;
	public InputStream inputStream;
	public JsonParser parser;

	public HttpRequest(String verb, String url, Iterable<ServalDHttpConnectionFactory.QueryParam> parms) throws UnsupportedEncodingException {
		this(verb, url + ServalDHttpConnectionFactory.QueryParam.encode(parms));
	}

	public HttpRequest(String verb, String url) {
		this.verb = verb;
		this.url = url;
	}

	public boolean connect(ServalDHttpConnectionFactory httpConnector) throws ServalDInterfaceException, IOException {
		httpConnection = httpConnector.newServalDHttpConnection(verb, url);
		httpConnection.connect();
		return checkResponse();
	}

	public void close() throws IOException {
		if (inputStream!=null) {
			inputStream.close();
			inputStream = null;
		}
	}

	public PostHelper beginPost(ServalDHttpConnectionFactory httpConnector) throws ServalDInterfaceException, IOException {
		httpConnection = httpConnector.newServalDHttpConnection(verb, url);
		PostHelper helper = new PostHelper(httpConnection);
		helper.connect();
		return helper;
	}

	public void setExpectedStatusCodes(int ... codes){
		expectedStatusCodes = codes;
	}

	public boolean isSuccessCode(){
		for(int i=0;i<expectedStatusCodes.length;i++)
			if (expectedStatusCodes[i]==httpStatusCode)
				return true;
		return false;
	}

	public boolean checkResponse() throws IOException, ServalDInterfaceException {
		if (expectedStatusCodes == null)
			setExpectedStatusCodes(HttpURLConnection.HTTP_OK);

		httpStatusCode = httpConnection.getResponseCode();
		httpStatusMessage = httpConnection.getResponseMessage();

		if (httpStatusCode >= 300)
			inputStream = httpConnection.getErrorStream();
		else
			inputStream = httpConnection.getInputStream();

		try {
			contentType = new ContentType(httpConnection.getContentType());
		} catch (ContentType.ContentTypeException e) {
			throw new ServalDInterfaceException("malformed HTTP Content-Type: " + httpConnection.getContentType(), e);
		}

		if (ContentType.applicationJson.matches(contentType))
			parser = new JsonParser(inputStream);

		if (isSuccessCode())
			return true;

		switch (httpStatusCode) {
			case HttpURLConnection.HTTP_NOT_IMPLEMENTED:
				throw new ServalDNotImplementedException(httpStatusMessage);
		}

		return false;
	}

	public String headerString(String header) throws ServalDInterfaceException
	{
		String str = httpConnection.getHeaderField(header);
		if (str == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return str;
	}

	public String headerQuotedStringOrNull(String header) throws ServalDInterfaceException
	{
		String quoted = httpConnection.getHeaderField(header);
		if (quoted == null)
			return null;
		if (quoted.length() == 0 || quoted.charAt(0) != '"')
			throw new ServalDInterfaceException("malformed header field: " + header + ": missing quote at start of quoted-string");
		boolean slosh = false;
		boolean end = false;
		StringBuilder b = new StringBuilder(quoted.length());
		for (int i = 1; i < quoted.length(); ++i) {
			char c = quoted.charAt(i);
			if (end)
				throw new ServalDInterfaceException("malformed header field: " + header + ": spurious character after quoted-string");
			if (c < ' ' || c > '~')
				throw new ServalDInterfaceException("malformed header field: " + header + ": invalid character in quoted-string");
			if (slosh) {
				b.append(c);
				slosh = false;
			}
			else if (c == '"')
				end = true;
			else if (c == '\\')
				slosh = true;
			else
				b.append(c);
		}
		if (!end)
			throw new ServalDInterfaceException("malformed header field: " + header + ": missing quote at end of quoted-string");
		return b.toString();
	}

	public Integer headerIntegerOrNull(String header) throws ServalDInterfaceException
	{
		String str = httpConnection.getHeaderField(header);
		if (str == null)
			return null;
		try {
			return Integer.valueOf(str);
		}
		catch (NumberFormatException e) {
		}
		throw new ServalDInterfaceException("invalid header field: " + header + ": " + str);
	}

	public Long headerUnsignedLongOrNull(String header) throws ServalDInterfaceException
	{
		String str = httpConnection.getHeaderField(header);
		if (str == null)
			return null;
		try {
			Long value = Long.valueOf(str);
			if (value >= 0)
				return value;
		}
		catch (NumberFormatException e) {
		}
		throw new ServalDInterfaceException("invalid header field: " + header + ": " + str);
	}

	public long headerUnsignedLong(String header) throws ServalDInterfaceException
	{
		Long value = headerUnsignedLongOrNull(header);
		if (value == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return value;
	}

	public <T> T headerOrNull(String header, Class<T> cls) throws ServalDInterfaceException
	{
		String str = httpConnection.getHeaderField(header);
		try {
			try {
				Constructor<T> constructor = cls.getConstructor(String.class);
				if (str == null)
					return null;
				return constructor.newInstance(str);
			}
			catch (NoSuchMethodException e) {
			}
			try {
				Method method = cls.getMethod("fromCode", Integer.TYPE);
				if ((method.getModifiers() & Modifier.STATIC) != 0 && method.getReturnType() == cls) {
					Integer integer = headerIntegerOrNull(header);
					if (integer == null)
						return null;
					return cls.cast(method.invoke(null, integer));
				}
			}
			catch (NoSuchMethodException e) {
			}
			throw new ServalDInterfaceException("don't know how to instantiate: " + cls.getName());
		}
		catch (ServalDInterfaceException e) {
			throw e;
		}
		catch (InvocationTargetException e) {
			throw new ServalDInterfaceException("invalid header field: " + header + ": " + str, e.getTargetException());
		}
		catch (Exception e) {
			throw new ServalDInterfaceException("invalid header field: " + header + ": " + str, e);
		}
	}

	public <T> T header(String header, Class<T> cls) throws ServalDInterfaceException
	{
		T value = headerOrNull(header, cls);
		if (value == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return value;
	}
}
