/**
 * Copyright (C) 2016-2017 Flinders University
 * Copyright (C) 2014-2015 Serval Project Inc.
 *
 * This file is part of Serval Software (http://www.servalproject.org)
 *
 * Serval Software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.servalproject.servaldna.rhizome;

import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.BundleSecret;
import org.servalproject.servaldna.ContentType;
import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

public class RhizomeCommon
{

	protected static ServalDInterfaceException unexpectedResponse(RhizomeRequest request) {
		return unexpectedResponse(request, null);
	}
	protected static ServalDInterfaceException unexpectedResponse(RhizomeRequest request, Throwable t) {
		return new ServalDInterfaceException(
				"unexpected Rhizome failure, " + quoteString(request.httpStatusMessage)
				+ (request.bundle_status_code == null ? "" : ", " + request.bundle_status_code)
				+ (request.bundle_status_message == null ? "" : " " + quoteString(request.bundle_status_message))
				+ (request.payload_status_code == null ? "" : ", " + request.payload_status_code)
				+ (request.payload_status_message == null ? "" : " " + quoteString(request.payload_status_message))
				+ " from " + request.url, t
			);
	}

	public static RhizomeManifestBundle rhizomeManifest(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException
	{
		RhizomeRequest request = new RhizomeRequest("GET", "/restful/rhizome/" + bid.toHex() + ".rhm");
		try {
			request.connect(connector);
			request.checkBundleStatus();
			switch (request.bundle_status_code) {
			case NEW:
				return null;
			case SAME:
				if (!RhizomeManifest.MIME_TYPE.matches(request.contentType))
					throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + request.contentType);
				RhizomeManifest manifest = RhizomeManifest.fromTextFormat(request.inputStream);
				RhizomeRequest.BundleExtra extra = request.bundleExtraFromHeaders();
				return new RhizomeManifestBundle(manifest, extra.rowId, extra.insertTime, extra.author, extra.secret);
			}
		}
		catch (RhizomeManifestParseException e) {
			throw new ServalDInterfaceException("malformed manifest from daemon", e);
		} catch (RhizomeFakeManifestException |
				RhizomeInconsistencyException |
				RhizomeInvalidManifestException |
				RhizomeReadOnlyException e) {
			throw unexpectedResponse(request, e);
		} finally {
			request.close();
		}
		throw unexpectedResponse(request);
	}

	public static RhizomePayloadRawBundle rhizomePayloadRaw(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException
	{
		RhizomeRequest request = new RhizomeRequest("GET", "/restful/rhizome/" + bid.toHex() + "/raw.bin");
		try {
			request.connect(connector);
			request.checkBundleStatus();
			switch (request.bundle_status_code) {
			case NEW: // No manifest
				return null;
			case SAME:
				if (request.payload_status_code == null)
					throw new ServalDInterfaceException("missing header field: Serval-Rhizome-Result-Payload-Status-Code");
				request.checkPayloadStatus();
				switch (request.payload_status_code) {
				case NEW:
					// The manifest is known but the payload is unavailable, so return a bundle
					// object with a null input stream.
					// FALL THROUGH
				case EMPTY:
					request.close();
					// FALL THROUGH
				case STORED: {
						if (request.inputStream != null && !ContentType.applicationOctetStream.matches(request.contentType))
							throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + request.contentType);
						RhizomeManifest manifest = request.manifestFromHeaders();
						RhizomeRequest.BundleExtra extra = request.bundleExtraFromHeaders();
						RhizomePayloadRawBundle ret = new RhizomePayloadRawBundle(manifest, request.inputStream, extra.rowId, extra.insertTime, extra.author, extra.secret);
						request.inputStream = null; // don't close when we return
						return ret;
					}
				}
			}
		} catch (RhizomeFakeManifestException |
				RhizomeInconsistencyException |
				RhizomeInvalidManifestException |
				RhizomeEncryptionException |
				RhizomeReadOnlyException e) {
			throw unexpectedResponse(request, e);
		} finally {
			request.close();
		}
		throw unexpectedResponse(request);
	}

	public static void WriteBundleZip(RhizomePayloadRawBundle payload, File output) throws IOException, RhizomeManifestSizeException {
		try{
			OutputStream out = new FileOutputStream(output);
			try{
				// read out all but the last two bytes
				long toWrite = payload.manifest.filesize - 2;
				byte[] buff = new byte[4096];
				while(toWrite>0){
					int len = toWrite > buff.length ? buff.length : (int) toWrite;
					len = payload.rawPayloadInputStream.read(buff, 0, len);
					out.write(buff, 0, len);
					toWrite -= len;
				}
				// assume the apk is a zip file, write the manifest into a zip file comment at the end
				byte[] manifestText = payload.manifest.toTextFormat();
				buff[0] = (byte) (manifestText.length & 0xFF);
				buff[1] = (byte) ((manifestText.length >> 8) & 0xFF);
				out.write(buff, 0, 2);
				out.write(manifestText);
			}finally{
				out.close();
			}
		}finally {
			payload.rawPayloadInputStream.close();
		}
	}

	public static RhizomePayloadBundle rhizomePayload(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException, RhizomeEncryptionException
	{
		RhizomeRequest request = new RhizomeRequest(
				"GET",
				"/restful/rhizome/" + bid.toHex() + "/decrypted.bin"
		);
		try {
			request.connect(connector);
			request.checkBundleStatus();
			switch (request.bundle_status_code) {
			case NEW: // No manifest
				return null;
			case SAME:
				if (request.payload_status_code == null)
					throw new ServalDInterfaceException("missing header field: Serval-Rhizome-Result-Payload-Status-Code");
				request.checkPayloadStatus();
				switch (request.payload_status_code) {
				case NEW:
					// The manifest is known but the payload is unavailable, so return a bundle
					// object with a null input stream.
					// FALL THROUGH
				case EMPTY:
					request.close();
					// FALL THROUGH
				case STORED: {
						if (request.inputStream != null && !ContentType.applicationOctetStream.matches(request.contentType))
							throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + request.contentType);
						RhizomeManifest manifest = request.manifestFromHeaders();
						RhizomeRequest.BundleExtra extra = request.bundleExtraFromHeaders();
						RhizomePayloadBundle ret = new RhizomePayloadBundle(manifest, request.inputStream, extra.rowId, extra.insertTime, extra.author, extra.secret);
						request.inputStream = null; // don't close when we return
						return ret;
					}
				}
			}
		} catch (RhizomeFakeManifestException |
				RhizomeInconsistencyException |
				RhizomeInvalidManifestException |
				RhizomeReadOnlyException e) {
			throw unexpectedResponse(request, e);
		}
		finally {
			request.close();
		}
		throw unexpectedResponse(request);
	}

	public static RhizomeInsertBundle rhizomeInsert(ServalDHttpConnectionFactory connector,
													SubscriberId author,
													RhizomeIncompleteManifest manifest,
													BundleSecret secret)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		return rhizomeInsert(connector, author, manifest, secret, null, null);
	}

	public static RhizomeInsertBundle rhizomeInsert(ServalDHttpConnectionFactory connector,
													SubscriberId author,
													RhizomeIncompleteManifest manifest,
													BundleSecret secret,
													InputStream payloadStream,
													String fileName)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		RhizomeRequest request = new RhizomeRequest("GET", "/restful/rhizome/insert");

		try {
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED);

			PostHelper helper = request.beginPost(connector);
			if (author != null)
				helper.writeField("bundle-author", author);
			if (secret != null)
				helper.writeField("bundle-secret", secret);
			helper.writeField("manifest", manifest);
			if (payloadStream != null)
				helper.writeField("payload", fileName, payloadStream);

			helper.close();

			request.checkResponse();
			request.checkPayloadStatus();
			request.checkBundleStatus();

			if (!RhizomeManifest.MIME_TYPE.matches(request.contentType))
				throw new ServalDInterfaceException("unexpected HTTP Content-Type " + request.contentType + " from " + request.url);

			RhizomeManifest returned_manifest = RhizomeManifest.fromTextFormat(request.inputStream);
			RhizomeRequest.BundleExtra extra = request.bundleExtraFromHeaders();
			return new RhizomeInsertBundle(request.bundle_status_code, request.payload_status_code, returned_manifest, extra.rowId, extra.insertTime, extra.author, extra.secret);
		}
		catch (RhizomeManifestParseException e) {
			throw new ServalDInterfaceException("malformed manifest from daemon", e);
		}
		finally {
			if (request.inputStream != null)
				request.inputStream.close();
		}
	}

	public static RhizomeImportStatus rhizomeImportZip(ServalDHttpConnectionFactory connector, File zipFile) throws ServalDInterfaceException, IOException, RhizomeException, RhizomeManifestSizeException, RhizomeManifestParseException {
		RandomAccessFile file = new RandomAccessFile(zipFile, "r");
		RhizomeManifest manifest = RhizomeManifest.fromZipComment(file);

		RhizomeRequest request = new RhizomeRequest(
				"GET",
				"/restful/rhizome/import?id="+manifest.id.toHex()+"&version="+manifest.version
		);
		try {
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK,
					HttpURLConnection.HTTP_CREATED,
					HttpURLConnection.HTTP_ACCEPTED);

			PostHelper helper = request.beginPost(connector);
			helper.writeField("manifest", manifest);
			OutputStream out = helper.beginFileField("payload", null);

			file.seek(0);

			long readLength = manifest.filesize-2;
			byte buff[] = new byte[4096];
			while (readLength>0){
				int len = readLength > buff.length ? buff.length : (int)readLength;
				int read = file.read(buff, 0, len);
				out.write(buff, 0, read);
				readLength -= read;
			}
			buff[0]=0;
			buff[1]=0;
			out.write(buff, 0, 2);

			helper.close();

			request.checkResponse();
			request.checkPayloadStatus();
			request.checkBundleStatus();
			return new RhizomeImportStatus(request.bundle_status_code, request.payload_status_code);

		}catch (ProtocolException e){
			// dodgy java implementation, only means that the server did not return 100-continue
			// attempting to read the input stream will fail again
			switch (request.httpConnection.getResponseCode()){
				case 200:
					return new RhizomeImportStatus(RhizomeBundleStatus.SAME, null);
				case 202:
					return new RhizomeImportStatus(RhizomeBundleStatus.OLD, null);
			}
			throw e;
		}
	}

	public static RhizomeImportStatus rhizomeImport(ServalDHttpConnectionFactory connector, RhizomeManifest manifest, InputStream payloadStream) throws ServalDInterfaceException, IOException, RhizomeException, RhizomeManifestSizeException {
		RhizomeRequest request = new RhizomeRequest(
				"GET",
				"/restful/rhizome/import?id="+manifest.id.toHex()+"&version="+manifest.version);
		try {
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK,
					HttpURLConnection.HTTP_CREATED,
					HttpURLConnection.HTTP_ACCEPTED);

			PostHelper helper = request.beginPost(connector);
			helper.writeField("manifest", manifest);
			if (manifest.filesize>0 && payloadStream != null)
				helper.writeField("payload", null, payloadStream);
			helper.close();

			request.checkResponse();
			request.checkPayloadStatus();
			request.checkBundleStatus();
			return new RhizomeImportStatus(request.bundle_status_code, request.payload_status_code);
		}catch (ProtocolException e){
			// dodgy java implementation, only means that the server did not return 100-continue
			// attempting to read the input stream will fail again
			switch (request.httpConnection.getResponseCode()){
				case 200:
					return new RhizomeImportStatus(RhizomeBundleStatus.SAME, null);
				case 202:
					return new RhizomeImportStatus(RhizomeBundleStatus.OLD, null);
			}
			throw e;
		}
	}

	public static String quoteString(String unquoted)
	{
		if (unquoted == null)
			return "null";
		StringBuilder b = new StringBuilder(unquoted.length() + 2);
		b.append('"');
		for (int i = 0; i < unquoted.length(); ++i) {
			char c = unquoted.charAt(i);
			if (c == '"' || c == '\\')
				b.append('\\');
			b.append(c);
		}
		b.append('"');
		return b.toString();
	}

}
