package org.servalproject.servaldna.keyring;

import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.AbstractId;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class KeyringRequest extends HttpRequest {
	public KeyringIdentity identity;

	public KeyringRequest(String verb, String url, Iterable<ServalDHttpConnectionFactory.QueryParam> parms) throws UnsupportedEncodingException {
		super(verb, url, parms);
	}

	public KeyringRequest(String verb, String url) {
		super(verb, url);
	}

	@Override
	public boolean checkResponse() throws IOException, ServalDInterfaceException {
		boolean ret = super.checkResponse();
		if (ret) {
			if (parser == null)
				throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + contentType);
			decodeJsonResult();
		}
		return ret;
	}

	public void decodeJsonResult() throws ServalDInterfaceException, IOException {
		try {
			if (parser.parse()!=JsonParser.ValueType.BeginObject)
				parser.expected("object");
			JsonParser.JsonMember member;
			while ((member = parser.nextMember()) != null) {
				if (member.name.equals("http_status_code") && member.type == JsonParser.ValueType.Number) {
					int hs = parser.readNumber().intValue();
					if (httpStatusCode ==0)
						httpStatusCode = hs;
					else if(hs != httpStatusCode)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", http_status_code=" + hs
								+ " but HTTP response code is " + httpStatusCode);
				}else if (member.name.equals("http_status_message") && member.type == JsonParser.ValueType.String) {
					httpStatusMessage = parser.readString();
				}else if (member.name.equals("identity") && member.type == JsonParser.ValueType.BeginObject){
					SubscriberId sid = null;
					SigningKey identity = null;
					String did = null;
					String name = null;
					while ((member = parser.nextMember()) != null) {
						if (member.name.equals("sid") && member.type == JsonParser.ValueType.String)
							sid = new SubscriberId(parser.readString());
						else if(member.name.equals("identity") && member.type == JsonParser.ValueType.String)
							identity = new SigningKey(parser.readString());
						else if (member.name.equals("did") && member.type == JsonParser.ValueType.String)
							did = parser.readString();
						else if (member.name.equals("name") && member.type == JsonParser.ValueType.String)
							name = parser.readString();
						else
							parser.skip(member.type);
					}
					this.identity = new KeyringIdentity(0,
							new Subscriber(sid, identity, true),
							did, name);
				} else
					parser.error("Unexpected "+member.type+" '"+member.name+"'");
			}
		} catch (JsonParser.JsonParseException |
				AbstractId.InvalidHexException e) {
			throw new ServalDInterfaceException("malformed JSON status response ("+httpStatusCode+" - "+httpStatusMessage+")", e);
		}
	}
}
