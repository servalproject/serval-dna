/**
 * Copyright (C) 2014 Serval Project Inc.
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

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import org.servalproject.servaldna.AbstractId;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.BundleKey;

public class RhizomeManifest {

	public final static int TEXT_FORMAT_MAX_SIZE = 8192;

	// Core fields used for routing and expiry (cannot be null)
	public final BundleId id;
	public final long version;
	public final long filesize;

	// Principal fields (can be null)
	public final FileHash filehash; // null iff filesize == 0
	public final SubscriberId sender;
	public final SubscriberId recipient;
	public final BundleKey BK;
	public final Long tail; // null iff not a journal
	public final Integer crypt;

	// Optional fields (all can be null)
	public final Long date; // can be null
	public final String service;
	public final String name;

	private HashMap<String,String> extraFields;
	private byte[] signatureBlock;
	private byte[] textFormat;

	protected RhizomeManifest(	BundleId id, 
								long version,
								long filesize,
								FileHash filehash,
								SubscriberId sender,
								SubscriberId recipient,
								BundleKey BK,
								Integer crypt,
								Long tail,
								Long date,
								String service,
								String name
								)
	{
		assert id != null;
		if (filesize == 0)
			assert filehash == null;
		else
			assert filehash != null;
		this.id = id;
		this.version = version;
		this.filesize = filesize;
		this.filehash = filehash;
		this.sender = sender;
		this.recipient = recipient;
		this.BK = BK;
		this.crypt = crypt;
		this.tail = tail;
		this.date = date;
		this.service = service;
		this.name = name;
		this.extraFields = null;
		this.signatureBlock = null;
		this.textFormat = null;
	}

	/** Return the Rhizome manifest in its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public byte[] toTextFormat() throws RhizomeManifestSizeException
	{
		if (textFormat == null) {
			try {
				ByteArrayOutputStream os = new ByteArrayOutputStream();
				OutputStreamWriter osw = new OutputStreamWriter(os, "US-ASCII");
				osw.write("id=" + id.toHex() + "\n");
				osw.write("version=" + version + "\n");
				osw.write("filesize=" + filesize + "\n");
				if (filehash != null)
					osw.write("filehash=" + filehash.toHex() + "\n");
				if (sender != null)
					osw.write("sender=" + sender.toHex() + "\n");
				if (recipient != null)
					osw.write("recipient=" + recipient.toHex() + "\n");
				if (BK != null)
					osw.write("BK=" + BK.toHex() + "\n");
				if (crypt != null)
					osw.write("crypt=" + crypt + "\n");
				if (tail != null)
					osw.write("tail=" + tail + "\n");
				if (date != null)
					osw.write("date=" + date + "\n");
				if (service != null)
					osw.write("service=" + service + "\n");
				if (name != null)
					osw.write("name=" + name + "\n");
				for (Map.Entry<String,String> e: extraFields.entrySet())
					osw.write(e.getKey() + "=" + e.getValue() + "\n");
				osw.flush();
				if (signatureBlock != null) {
					os.write(0);
					os.write(signatureBlock);
				}
				osw.close();
				if (os.size() > TEXT_FORMAT_MAX_SIZE)
					throw new RhizomeManifestSizeException("manifest text format overflow", os.size(), TEXT_FORMAT_MAX_SIZE);
				textFormat = os.toByteArray();
			}
			catch (IOException e) {
				// should not happen with ByteArrayOutputStream
				return new byte[0];
			}
		}
		byte[] ret = new byte[textFormat.length];
		System.arraycopy(textFormat, 0, ret, 0, ret.length);
		return ret;
	}

	/** Construct a Rhizome manifest from its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	static public RhizomeManifest fromTextFormat(byte[] bytes) throws RhizomeManifestParseException
	{
		return fromTextFormat(bytes, 0, bytes.length);
	}

	/** Construct a Rhizome manifest from its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	static public RhizomeManifest fromTextFormat(byte[] bytes, int off, int len) throws RhizomeManifestParseException
	{
		// The signature block follows the first nul character at the start of a line.
		byte[] sigblock = null;
		int proplen = len;
		for (int i = 0; i < len; ++i) {
			if (bytes[off + i] == 0 && (i == 0 || bytes[off + i - 1] == '\n')) {
				sigblock = new byte[len - i - 1];
				System.arraycopy(bytes, off + i + 1, sigblock, 0, sigblock.length);
				proplen = i;
				break;
			}
		}
		String text;
		try {
			text = new String(bytes, off, proplen, "US-ASCII");
		}
		catch (UnsupportedEncodingException e) {
			throw new RhizomeManifestParseException(e);
		}
		BundleId id = null;
		Long version = null;
		Long filesize = null;
		FileHash filehash = null;
		SubscriberId sender = null;
		SubscriberId recipient = null;
		BundleKey BK = null;
		Integer crypt = null;
		Long tail = null;
		Long date = null;
		String service = null;
		String name = null;
		HashMap<String,String> extras = new HashMap<String,String>();
		int pos = 0;
		int lnum = 1;
		while (pos < text.length()) {
			int nl = text.indexOf('\n', pos);
			if (nl == -1)
				nl = text.length();
			int field = pos;
			if (!isFieldNameFirstChar(text.charAt(field)))
				throw new RhizomeManifestParseException("invalid field name at line " + lnum + ": " + text.substring(pos, nl - pos));
			++field;
			while (isFieldNameChar(text.charAt(field)))
				++field;
			assert field < nl;
			if (text.charAt(field) != '=')
				throw new RhizomeManifestParseException("invalid field name at line " + lnum + ": " + text.substring(pos, nl - pos));
			String fieldName = text.substring(pos, field);
			String fieldValue = text.substring(field + 1, nl);
			HashSet<String> fieldNames = new HashSet<String>(50);
			try {
				if (fieldNames.contains(fieldName))
					throw new RhizomeManifestParseException("duplicate field at line " + lnum + ": " + text.substring(pos, nl - pos));
				fieldNames.add(fieldName);
				if (fieldName.equals("id"))
					id = new BundleId(fieldValue);
				else if (fieldName.equals("version"))
					version = parseUnsignedLong(fieldValue);
				else if (fieldName.equals("filesize"))
					filesize = parseUnsignedLong(fieldValue);
				else if (fieldName.equals("filehash"))
					filehash = new FileHash(fieldValue);
				else if (fieldName.equals("sender"))
					sender = new SubscriberId(fieldValue);
				else if (fieldName.equals("recipient"))
					recipient = new SubscriberId(fieldValue);
				else if (fieldName.equals("BK"))
					BK = new BundleKey(fieldValue);
				else if (fieldName.equals("crypt"))
					crypt = Integer.parseInt(fieldValue);
				else if (fieldName.equals("tail"))
					tail = parseUnsignedLong(fieldValue);
				else if (fieldName.equals("date"))
					date = parseUnsignedLong(fieldValue);
				else if (fieldName.equals("service"))
					service = fieldValue;
				else if (fieldName.equals("name"))
					name = fieldValue;
				else
					extras.put(fieldName, fieldValue);
			}
			catch (AbstractId.InvalidHexException e) {
				throw new RhizomeManifestParseException("invalid value at line " + lnum + ": " + text.substring(pos, nl - pos), e);
			}
			catch (NumberFormatException e) {
				throw new RhizomeManifestParseException("invalid value at line " + lnum + ": " + text.substring(pos, nl - pos), e);
			}
			pos = nl + 1;
		}
		if (id == null)
			throw new RhizomeManifestParseException("missing 'id' field");
		if (version == null)
			throw new RhizomeManifestParseException("missing 'version' field");
		if (filesize == null)
			throw new RhizomeManifestParseException("missing 'filesize' field");
		if (filesize != 0 && filehash == null)
			throw new RhizomeManifestParseException("missing 'filehash' field");
		else if (filesize == 0 && filehash != null)
			throw new RhizomeManifestParseException("spurious 'filehash' field");
		RhizomeManifest m = new RhizomeManifest(id, version, filesize, filehash, sender, recipient, BK, crypt, tail, date, service, name);
		m.extraFields = extras;
		m.signatureBlock = sigblock;
		m.textFormat = new byte[len];
		System.arraycopy(bytes, off, m.textFormat, 0, m.textFormat.length);
		return m;
	}

	/** Convenience method: construct a Rhizome manifest from all the bytes read from a given
	 * InputStream.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	static public RhizomeManifest fromTextFormat(InputStream in) throws IOException, RhizomeManifestParseException
	{
		byte[] bytes = new byte[TEXT_FORMAT_MAX_SIZE];
		int n = 0;
		int offset = 0;
		while (offset < bytes.length && (n = in.read(bytes, offset, bytes.length - offset)) != -1)
			offset += n;
		assert offset <= bytes.length;
		if (offset == bytes.length)
			n = in.read();
		if (n != -1)
			throw new RhizomeManifestParseException("input stream too long");
		return fromTextFormat(bytes, 0, offset);
	}

	private static boolean isFieldNameFirstChar(char c)
	{
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
	}

	private static boolean isFieldNameChar(char c)
	{
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
	}

	private static Long parseUnsignedLong(String text) throws NumberFormatException
	{
		Long value = Long.valueOf(text);
		if (value < 0)
			throw new NumberFormatException("negative value not allowed");
		return value;
	}

}
