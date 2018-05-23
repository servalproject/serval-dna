package org.servalproject.servaldna;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class ServalDUnexpectedHttpStatus extends ServalDInterfaceException {
	public final int responseCode;
	public final String responseMessage;
	public final URL url;
	public ServalDUnexpectedHttpStatus(HttpURLConnection httpConnection) throws IOException {
		super("received unexpected HTTP Status "+
				httpConnection.getResponseCode()+" " + httpConnection.getResponseMessage()+" from " + httpConnection.getURL());
		this.responseCode = httpConnection.getResponseCode();
		this.responseMessage = httpConnection.getResponseMessage();
		this.url = httpConnection.getURL();
	}
}
