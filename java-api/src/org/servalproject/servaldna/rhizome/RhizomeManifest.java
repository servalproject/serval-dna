/**
 * Copyright (C) 2017 Flinders University
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

import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.servalproject.servaldna.AbstractId;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.BundleKey;

public class RhizomeManifest {

	public final static int TEXT_FORMAT_MAX_SIZE = 8192;
	public static final String MIME_TYPE = "rhizome/manifest; format=\"text+binarysig\"";

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

	protected HashMap<String,String> extraFields;
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

	protected RhizomeManifest(RhizomeIncompleteManifest m)
	{
		this(m.id, m.version, m.filesize, m.filehash, m.sender, m.recipient, m.BK, m.crypt, m.tail, m.date, m.service, m.name);
	}

	/** Return the Rhizome manifest in its text format representation, with the signature block at
	 * the end if present.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public byte[] toTextFormat() throws RhizomeManifestSizeException {
		buildTextformat();
		byte[] ret = new byte[this.textFormat.length];
		System.arraycopy(this.textFormat, 0, ret, 0, ret.length);
		return ret;
	}


	private void buildTextformat() throws RhizomeManifestSizeException {
		if (textFormat!=null)
			return;
		try{
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			try {
				new RhizomeIncompleteManifest(this).toTextFormat(os);
				if (signatureBlock!=null) {
					os.write(0);
					os.write(this.signatureBlock);
				}
				if (os.size() > TEXT_FORMAT_MAX_SIZE)
					throw new RhizomeManifestSizeException("manifest text format overflow", os.size(), TEXT_FORMAT_MAX_SIZE);
				textFormat = os.toByteArray();
			} finally{
				os.close();
			}
		} catch (IOException e) {
			// Um....
		}
	}

	/** Write the Rhizome manifest in its text format representation to the given output stream,
	 * with the signature block at the end if present.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public void toTextFormat(OutputStream os) throws IOException, RhizomeManifestSizeException {
		buildTextformat();
		os.write(this.textFormat);
	}

	/** Construct a Rhizome manifest from its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	static public RhizomeManifest fromTextFormat(byte[] bytes) throws RhizomeManifestParseException
	{
		return fromTextFormat(bytes, 0, bytes.length);
	}

	/** Construct a complete Rhizome manifest from its text format representation, including a
	 * trailing signature block.
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
		RhizomeIncompleteManifest im = new RhizomeIncompleteManifest();
		try {
			im.parseTextFormat(new ByteArrayInputStream(bytes, off, proplen));
		}
		catch (IOException e) {
		}
		if (im.id == null)
			throw new RhizomeManifestParseException("missing 'id' field");
		if (im.version == null)
			throw new RhizomeManifestParseException("missing 'version' field");
		if (im.filesize == null)
			throw new RhizomeManifestParseException("missing 'filesize' field");
		if (im.filesize != 0 && im.filehash == null)
			throw new RhizomeManifestParseException("missing 'filehash' field");
		else if (im.filesize == 0 && im.filehash != null)
			throw new RhizomeManifestParseException("spurious 'filehash' field");
		RhizomeManifest m = new RhizomeManifest(im);
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
	public static RhizomeManifest fromTextFormat(InputStream in) throws IOException, RhizomeManifestParseException
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

	public static RhizomeManifest fromTextFormat(File manifestFile) throws IOException, RhizomeManifestParseException {
		InputStream in = new FileInputStream(manifestFile);
		try {
			return fromTextFormat(in);
		}finally {
			in.close();
		}
	}

	public static RhizomeManifest fromZipComment(RandomAccessFile file) throws IOException, RhizomeManifestParseException {
		int readLen = RhizomeManifest.TEXT_FORMAT_MAX_SIZE + 22;
		file.seek(file.length() - readLen);
		byte buff[] = new byte[readLen];
		file.readFully(buff);
		int offset = buff.length - 21;
		while(offset>0) {
			if (buff[--offset] != 0x06)
				continue;
			if (buff[--offset] != 0x05)
				continue;
			if (buff[--offset] != 0x4b)
				continue;
			if (buff[--offset] != 0x50)
				continue;

			// located zip EOCD record marker 0x504b0506
			offset += 20;
			int manifestLen = (buff[offset++]&0xFF) | ((buff[offset++] & 0xFF) << 8);
			if (manifestLen != readLen - offset)
				throw new RhizomeManifestParseException("Zip Comment length ("+manifestLen+") doesn't align with end of file ("+readLen+", "+offset+")");
			if (manifestLen == 0)
				throw new RhizomeManifestParseException("No Zip Comment");

			RhizomeManifest manifest = RhizomeManifest.fromTextFormat(buff, offset, manifestLen);
			long expectedFileSize = file.length() - readLen + offset;
			if (manifest.filesize != expectedFileSize)
				throw new RhizomeManifestParseException("Manifest filesize doesn't match zip file length");
			return manifest;
		}
		throw new RhizomeManifestParseException("Zip EOCD record not found");
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
