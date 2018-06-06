package org.servalproject.servaldna.meshms;

import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDUnexpectedHttpStatus;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class MeshMSRequest extends HttpRequest {
	public MeshMSStatus meshms_status_code;
	public String meshms_status_message;

	public MeshMSRequest(String verb, String url, Iterable<ServalDHttpConnectionFactory.QueryParam> parms) throws UnsupportedEncodingException {
		super(verb, url, parms);
	}

	public MeshMSRequest(String verb, String url) {
		super(verb, url);
	}

	public void decodeJson() throws IOException, ServalDInterfaceException {
		try{
			if (parser==null)
				throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + contentType);
			if (parser.parse()!=JsonParser.ValueType.BeginObject)
				parser.expected("object");
			JsonParser.JsonMember member;
			while((member = parser.nextMember())!=null) {
				if (member.name.equals("http_status_code") && member.type == JsonParser.ValueType.Number) {
					int hs = parser.readNumber().intValue();
					if (httpStatusCode == 0)
						httpStatusCode = hs;
					else if (hs != httpStatusCode)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", http_status_code=" + hs
								+ " but HTTP response code is " + httpStatusCode);
				} else if (member.name.equals("http_status_message") && member.type == JsonParser.ValueType.String) {
					httpStatusMessage = parser.readString();
				} else if (member.name.equals("meshms_status_code") && member.type == JsonParser.ValueType.Number) {
					meshms_status_code = MeshMSStatus.fromCode(parser.readNumber().intValue());
				} else if (member.name.equals("meshms_status_message") && member.type == JsonParser.ValueType.String) {
					meshms_status_message = parser.readString();
				} else
					parser.error("Unexpected "+member.type+" '"+member.name+"'");
			}

			boolean success = isSuccessCode();
			if (meshms_status_code == null) {
				if (!success)
					throw new ServalDUnexpectedHttpStatus(httpConnection);
				throw new ServalDFailureException("missing meshms_status_code from " + url);
			}

			switch (meshms_status_code) {
				case OK:
				case UPDATED:
					if (!success)
						throw new ServalDUnexpectedHttpStatus(httpConnection);
					break;
				case SID_LOCKED:
					throw new MeshMSUnknownIdentityException(httpConnection.getURL());
				case PROTOCOL_FAULT:
					throw new MeshMSProtocolFaultException(httpConnection.getURL());
				case ERROR:
					throw new ServalDFailureException("received meshms_status_code=ERROR(-1) from " + url);
			}
		} catch (JsonParser.JsonParseException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}
}
