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

import org.servalproject.servaldna.AbstractId;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.BundleKey;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.SubscriberId;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

public class RhizomeIncompleteManifest {

	public BundleId id;
	public Long version;
	public Long filesize;
	public FileHash filehash;
	public SubscriberId sender;
	public SubscriberId recipient;
	public BundleKey BK;
	public Long tail;
	public Integer crypt;
	public Long date;
	public String service;
	public String name;
	private HashMap<String,String> extraFields;

	public RhizomeIncompleteManifest()
	{
		this.extraFields = new HashMap<String,String>();
	}

	@SuppressWarnings("unchecked")
	public RhizomeIncompleteManifest(RhizomeManifest m)
	{
		this.id = m.id;
		this.version = m.version;
		this.filesize = m.filesize;
		this.filehash = m.filehash;
		this.sender = m.sender;
		this.recipient = m.recipient;
		this.BK = m.BK;
		this.crypt = m.crypt;
		this.tail = m.tail;
		this.date = m.date;
		this.service = m.service;
		this.name = m.name;
		this.extraFields = (HashMap<String,String>) m.extraFields.clone(); // unchecked cast
	}

	/** Return the Rhizome manifest in its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public void toTextFormat(PrintStream writer){
		if (id != null)
			writer.print("id=" + id.toHex() + "\n");
		if (version != null)
			writer.print("version=" + version + "\n");
		if (filesize != null)
			writer.print("filesize=" + filesize + "\n");
		if (filehash != null)
			writer.print("filehash=" + filehash.toHex() + "\n");
		if (sender != null)
			writer.print("sender=" + sender.toHex() + "\n");
		if (recipient != null)
			writer.print("recipient=" + recipient.toHex() + "\n");
		if (BK != null)
			writer.print("BK=" + BK.toHex() + "\n");
		if (crypt != null)
			writer.print("crypt=" + crypt + "\n");
		if (tail != null)
			writer.print("tail=" + tail + "\n");
		if (date != null)
			writer.print("date=" + date + "\n");
		if (service != null)
			writer.print("service=" + service + "\n");
		if (name != null)
			writer.print("name=" + name + "\n");
		for (Map.Entry<String,String> e: extraFields.entrySet())
			writer.print(e.getKey() + "=" + e.getValue() + "\n");
	}

	public void toTextFormat(OutputStream os) throws IOException
	{
		PrintStream wr = new PrintStream(os, false, "UTF-8");
		toTextFormat(wr);
		wr.flush();
	}

	/** Construct a Rhizome manifest from its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public static RhizomeIncompleteManifest fromTextFormat(byte[] bytes) throws RhizomeManifestParseException
	{
		RhizomeIncompleteManifest m = new RhizomeIncompleteManifest();
		try {
			m.parseTextFormat(new ByteArrayInputStream(bytes, 0, bytes.length));
		}
		catch (IOException e) {
		}
		return m;
	}

	/** Construct a Rhizome manifest from its text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public static RhizomeIncompleteManifest fromTextFormat(byte[] bytes, int off, int len) throws RhizomeManifestParseException
	{
		RhizomeIncompleteManifest m = new RhizomeIncompleteManifest();
		try {
			m.parseTextFormat(new ByteArrayInputStream(bytes, off, len));
		}
		catch (IOException e) {
		}
		return m;
	}

	/** Convenience method: construct a Rhizome manifest from all the bytes read from a given
	 * InputStream.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	static public RhizomeIncompleteManifest fromTextFormat(InputStream in) throws IOException, RhizomeManifestParseException
	{
		RhizomeIncompleteManifest m = new RhizomeIncompleteManifest();
		m.parseTextFormat(in);
		return m;
	}

	/** Fill in manifest fields from a text format representation.
	 *
	 * @author Andrew Bettison <andrew@servalproject.com>
	 */
	public void parseTextFormat(InputStream in) throws IOException, RhizomeManifestParseException
	{
		try {
			InputStreamReader inr = new InputStreamReader(in, "UTF-8");
			int pos = 0;
			int lnum = 1;
			int eq = -1;
			StringBuilder line = new StringBuilder();
			while (true) {
				int c = inr.read();
				if (c != -1 && c != '\n') {
					if (eq == -1 && c == '=')
						eq = line.length();
					line.append((char)c);
				}
				else if (line.length() == 0)
					break;
				else if (eq < 1)
					throw new RhizomeManifestParseException("malformed (missing '=') at line " + lnum + ": " + line);
				else {
					String fieldName = line.substring(0, eq);
					String fieldValue = line.substring(eq + 1);
					if (!isFieldNameFirstChar(fieldName.charAt(0)))
						throw new RhizomeManifestParseException("invalid field name at line " + lnum + ": " + line);
					for (int i = 1; i < fieldName.length(); ++i)
						if (!isFieldNameChar(fieldName.charAt(i)))
							throw new RhizomeManifestParseException("invalid field name at line " + lnum + ": " + line);
					try {
						if (fieldName.equals("id"))
							this.id = parseField(this.id, new BundleId(fieldValue));
						else if (fieldName.equals("version"))
							this.version = parseField(this.version, parseUnsignedLong(fieldValue));
						else if (fieldName.equals("filesize"))
							this.filesize = parseField(this.filesize, parseUnsignedLong(fieldValue));
						else if (fieldName.equals("filehash"))
							this.filehash = parseField(this.filehash, new FileHash(fieldValue));
						else if (fieldName.equals("sender"))
							this.sender = parseField(this.sender, new SubscriberId(fieldValue));
						else if (fieldName.equals("recipient"))
							this.recipient = parseField(this.recipient, new SubscriberId(fieldValue));
						else if (fieldName.equals("BK"))
							this.BK = parseField(this.BK, new BundleKey(fieldValue));
						else if (fieldName.equals("crypt"))
							this.crypt = parseField(this.crypt, Integer.parseInt(fieldValue));
						else if (fieldName.equals("tail"))
							this.tail = parseField(this.tail, parseUnsignedLong(fieldValue));
						else if (fieldName.equals("date"))
							this.date = parseField(this.date, parseUnsignedLong(fieldValue));
						else if (fieldName.equals("service"))
							this.service = parseField(this.service, fieldValue);
						else if (fieldName.equals("name"))
							this.name = parseField(this.name, fieldValue);
						else if (this.extraFields.containsKey(fieldName))
							throw new RhizomeManifestParseException("duplicate field");
						else
							this.extraFields.put(fieldName, fieldValue);
					}
					catch (RhizomeManifestParseException e) {
						throw new RhizomeManifestParseException(e.getMessage() + " at line " + lnum + ": " + line);
					}
					catch (AbstractId.InvalidHexException e) {
						throw new RhizomeManifestParseException("invalid value at line " + lnum + ": " + line, e);
					}
					catch (NumberFormatException e) {
						throw new RhizomeManifestParseException("invalid value at line " + lnum + ": " + line, e);
					}
					line.setLength(0);
					eq = -1;
					++lnum;
				}
			}
			if (line.length() > 0)
				throw new RhizomeManifestParseException("malformed (missing newline) at line " + lnum + ": " + line);
		}
		catch (UnsupportedEncodingException e) {
			throw new RhizomeManifestParseException(e);
		}
	}

	static private <T> T parseField(T currentValue, T newValue) throws RhizomeManifestParseException
	{
		if (currentValue == null)
			return newValue;
		if (!currentValue.equals(newValue))
			throw new RhizomeManifestParseException("duplicate field");
		return currentValue;
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
