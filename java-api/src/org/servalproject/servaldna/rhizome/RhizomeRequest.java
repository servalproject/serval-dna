package org.servalproject.servaldna.rhizome;

import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.BundleKey;
import org.servalproject.servaldna.BundleSecret;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDNotImplementedException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;

class RhizomeRequest extends HttpRequest {
	RhizomeBundleStatus bundle_status_code;
	String bundle_status_message;
	RhizomePayloadStatus payload_status_code;
	String payload_status_message;

	public RhizomeRequest(String verb, String url, Iterable<ServalDHttpConnectionFactory.QueryParam> parms) throws UnsupportedEncodingException {
		super(verb, url, parms);
	}

	public RhizomeRequest(String verb, String url) {
		super(verb, url);
	}

	@Override
	public boolean checkResponse() throws IOException, ServalDInterfaceException {
		boolean ret = super.checkResponse();

		bundle_status_code = headerOrNull("Serval-Rhizome-Result-Bundle-Status-Code", RhizomeBundleStatus.class);
		bundle_status_message = headerQuotedStringOrNull("Serval-Rhizome-Result-Bundle-Status-Message");
		payload_status_code = headerOrNull("Serval-Rhizome-Result-Payload-Status-Code", RhizomePayloadStatus.class);
		payload_status_message = headerQuotedStringOrNull("Serval-Rhizome-Result-Payload-Status-Message");

		if (ret)
			return true;
		if (parser==null)
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + contentType);
		decodeFailureJson();
		switch (httpStatusCode) {
			case HttpURLConnection.HTTP_FORBIDDEN: // for crypto failure (missing secret)
			case HttpURLConnection.HTTP_NOT_FOUND: // for unknown BID or rhizome disabled
			case 419: // Authentication Timeout, for missing secret
			case 422: // Unprocessable Entity, for invalid/malformed manifest
			case 423: // Locked, for database busy
			case 429: // Too Many Requests, for out of manifests
				return false;
			case HttpURLConnection.HTTP_NOT_IMPLEMENTED:
				throw new ServalDNotImplementedException(httpStatusMessage);
		}
		throw new ServalDInterfaceException("unexpected HTTP response: " + httpStatusCode + " " + httpStatusMessage);
	}

	public void checkBundleStatus() throws ServalDInterfaceException, RhizomeReadOnlyException, RhizomeInconsistencyException, RhizomeFakeManifestException, RhizomeInvalidManifestException {
		if (bundle_status_code == null)
			throw new ServalDInterfaceException("missing header field: Serval-Rhizome-Result-Bundle-Status-Code");
		switch (bundle_status_code) {
			case ERROR:
				throw new ServalDFailureException("received Rhizome bundle_status=ERROR " + RhizomeCommon.quoteString(bundle_status_message) + " from " + url);
			case INVALID:
				throw new RhizomeInvalidManifestException(bundle_status_message, httpConnection.getURL());
			case FAKE:
				throw new RhizomeFakeManifestException(bundle_status_message, httpConnection.getURL());
			case INCONSISTENT:
				throw new RhizomeInconsistencyException(bundle_status_message, httpConnection.getURL());
			case READONLY:
				throw new RhizomeReadOnlyException(bundle_status_message, httpConnection.getURL());
		}
	}

	public void checkPayloadStatus() throws ServalDFailureException, RhizomeInconsistencyException, RhizomeEncryptionException {
		if (payload_status_code == null)
			return;
		switch (payload_status_code) {
			case ERROR:
				throw new ServalDFailureException("received Rhizome payload_status=ERROR " +
						RhizomeCommon.quoteString(payload_status_message) + " from " + url);
			case WRONG_SIZE:
			case WRONG_HASH:
				throw new RhizomeInconsistencyException(payload_status_message, httpConnection.getURL());
			case CRYPTO_FAIL:
				throw new RhizomeEncryptionException(payload_status_message, httpConnection.getURL());
		}
	}

	public BundleExtra bundleExtraFromHeaders() throws ServalDInterfaceException
	{
		BundleExtra extra = new BundleExtra();
		extra.rowId = headerUnsignedLongOrNull("Serval-Rhizome-Bundle-Rowid");
		extra.insertTime = headerUnsignedLongOrNull("Serval-Rhizome-Bundle-Inserttime");
		extra.author = headerOrNull("Serval-Rhizome-Bundle-Author", SubscriberId.class);
		extra.secret = headerOrNull("Serval-Rhizome-Bundle-Secret", BundleSecret.class);
		return extra;
	}

	public RhizomeManifest manifestFromHeaders() throws ServalDInterfaceException
	{
		BundleId id = header("Serval-Rhizome-Bundle-Id", BundleId.class);
		long version = headerUnsignedLong("Serval-Rhizome-Bundle-Version");
		long filesize = headerUnsignedLong("Serval-Rhizome-Bundle-Filesize");
		FileHash filehash = filesize == 0 ? null : header("Serval-Rhizome-Bundle-Filehash", FileHash.class);
		SubscriberId sender = headerOrNull("Serval-Rhizome-Bundle-Sender", SubscriberId.class);
		SubscriberId recipient = headerOrNull("Serval-Rhizome-Bundle-Recipient", SubscriberId.class);
		BundleKey BK = headerOrNull("Serval-Rhizome-Bundle-BK", BundleKey.class);
		Integer crypt = headerIntegerOrNull("Serval-Rhizome-Bundle-Crypt");
		Long tail = headerUnsignedLongOrNull("Serval-Rhizome-Bundle-Tail");
		Long date = headerUnsignedLongOrNull("Serval-Rhizome-Bundle-Date");
		String service = httpConnection.getHeaderField("Serval-Rhizome-Bundle-Service");
		String name = headerQuotedStringOrNull("Serval-Rhizome-Bundle-Name");
		return new RhizomeManifest(id, version, filesize, filehash, sender, recipient, BK, crypt, tail, date, service, name);
	}

	public void decodeFailureJson() throws IOException, ServalDInterfaceException{
		try {
			if (parser.parse()!=JsonParser.ValueType.BeginObject)
				parser.expected("object");
			JsonParser.JsonMember member;
			while((member = parser.nextMember())!=null){
				if (member.name.equals("http_status_code") && member.type == JsonParser.ValueType.Number) {
					int hs = parser.readNumber().intValue();
					if (httpStatusCode ==0)
						httpStatusCode = hs;
					else if(hs != httpStatusCode)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", http_status_code=" + hs
								+ " but HTTP response code is " + httpStatusCode);
				}else if (member.name.equals("http_status_message") && member.type == JsonParser.ValueType.String){
					httpStatusMessage = parser.readString();
				}else if (member.name.equals("rhizome_bundle_status_code") && member.type == JsonParser.ValueType.Number) {
					RhizomeBundleStatus bs = RhizomeBundleStatus.fromCode(parser.readNumber().intValue());
					if (bundle_status_code == null)
						bundle_status_code = bs;
					else if (bundle_status_code != bs)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_bundle_status_code=" + bs.code
								+ " but Serval-Rhizome-Result-Bundle-Status-Code: " + bundle_status_code.code);
				} else if (member.name.equals("rhizome_bundle_status_message") && member.type == JsonParser.ValueType.String) {
					String message = parser.readString();
					if (bundle_status_message == null)
						bundle_status_message = message;
					else if (!bundle_status_message.equals(message))
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_bundle_status_message=" + message
								+ " but Serval-Rhizome-Result-Bundle-Status-Message: " + bundle_status_message);
				} else if (member.name.equals("rhizome_payload_status_code") && member.type == JsonParser.ValueType.Number) {
					RhizomePayloadStatus bs = RhizomePayloadStatus.fromCode(parser.readNumber().intValue());
					if (payload_status_code == null)
						payload_status_code = bs;
					else if (payload_status_code != bs)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_payload_status_code=" + bs.code
								+ " but Serval-Rhizome-Result-Payload-Status-Code: " + payload_status_code.code);
				} else if (member.name.equals("rhizome_payload_status_message") && member.type == JsonParser.ValueType.String) {
					String message = parser.readString();
					if (payload_status_message == null)
						payload_status_message = message;
					else if (!payload_status_message.equals(message))
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_payload_status_message=" + message
								+ " but Serval-Rhizome-Result-Payload-Status-Code: " + payload_status_message);
				} else
					parser.error("Unexpected "+member.type+" '"+member.name+"'");
			}
		}
		catch (JsonParser.JsonParseException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

	public static class BundleExtra {
		public Long rowId;
		public Long insertTime;
		public SubscriberId author;
		public BundleSecret secret;
	}
}
