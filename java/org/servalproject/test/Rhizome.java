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

package org.servalproject.test;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServerControl;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.BundleSecret;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.rhizome.RhizomeManifest;
import org.servalproject.servaldna.rhizome.RhizomeIncompleteManifest;
import org.servalproject.servaldna.rhizome.RhizomeListBundle;
import org.servalproject.servaldna.rhizome.RhizomeBundleList;
import org.servalproject.servaldna.rhizome.RhizomeManifestBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadRawBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadBundle;
import org.servalproject.servaldna.rhizome.RhizomeInsertBundle;
import org.servalproject.servaldna.rhizome.RhizomeException;
import org.servalproject.servaldna.rhizome.RhizomeManifestParseException;

public class Rhizome {

	static String manifestFields(RhizomeManifest manifest, String sep)
	{
		return	        "id=" + manifest.id
				+ sep + "version=" + manifest.version
				+ sep + "filesize=" + manifest.filesize
				+ (manifest.filesize != 0 ? sep + "filehash=" + manifest.filehash : "")
				+ (manifest.sender != null ? sep + "sender=" + manifest.sender : "")
				+ (manifest.recipient != null ? sep + "recipient=" + manifest.recipient : "")
				+ (manifest.date != null ? sep + "date=" + manifest.date : "")
				+ (manifest.service != null ? sep + "service=" + manifest.service : "")
				+ (manifest.BK != null ? sep + "BK=" + manifest.BK : "")
				+ (manifest.name != null ? sep + "name=" + manifest.name : "");
	}

	static void rhizome_list() throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		RhizomeBundleList list = null;
		try {
			list = client.rhizomeListBundles();
			RhizomeListBundle bundle;
			while ((bundle = list.nextBundle()) != null) {
				System.out.println(
						"_token=" + bundle.token +
						", _rowId=" + bundle.rowId +
						", _insertTime=" + bundle.insertTime +
						", _author=" + bundle.author +
						", _fromHere=" + bundle.fromHere +
						", " + manifestFields(bundle.manifest, ", ")
					);
			}
		}
		finally {
			if (list != null)
				list.close();
		}
		System.exit(0);
	}

	static void rhizome_manifest(BundleId bid, String dstpath) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		RhizomeManifestBundle bundle = client.rhizomeManifest(bid);
		if (bundle == null)
			System.out.println("not found");
		else {
			System.out.println(
					(bundle.rowId == null ? "" : "_rowId=" + bundle.rowId + "\n") +
					(bundle.insertTime == null ? "" : "_insertTime=" + bundle.insertTime + "\n") +
					(bundle.author == null ? "" : "_author=" + bundle.author + "\n") +
					(bundle.secret == null ? "" : "_secret=" + bundle.secret + "\n") +
					manifestFields(bundle.manifest, "\n") + "\n"
				);
			FileOutputStream out = new FileOutputStream(dstpath);
			out.write(bundle.manifestText());
			out.close();
		}
		System.exit(0);
	}

	static void rhizome_payload_raw(BundleId bid, String dstpath) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		FileOutputStream out = null;
		try {
			RhizomePayloadRawBundle bundle = client.rhizomePayloadRaw(bid);
			if (bundle == null)
				System.out.println("not found");
			else {
				InputStream in = bundle.rawPayloadInputStream;
				if (in == null)
					System.out.println("no payload");
				else {
					out = new FileOutputStream(dstpath);
					byte[] buf = new byte[4096];
					int n;
					while ((n = in.read(buf)) > 0)
						out.write(buf, 0, n);
					in.close();
					out.close();
					out = null;
				}
				System.out.println(
						(bundle.rowId == null ? "" : "_rowId=" + bundle.rowId + "\n") +
						(bundle.insertTime == null ? "" : "_insertTime=" + bundle.insertTime + "\n") +
						(bundle.author == null ? "" : "_author=" + bundle.author + "\n") +
						(bundle.secret == null ? "" : "_secret=" + bundle.secret + "\n") +
						manifestFields(bundle.manifest, "\n") + "\n"
					);
			}
		}
		finally {
			if (out != null)
				out.close();
		}
		System.exit(0);
	}

	static void rhizome_payload_decrypted(BundleId bid, String dstpath) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		FileOutputStream out = null;
		try {
			RhizomePayloadBundle bundle = client.rhizomePayload(bid);
			if (bundle == null)
				System.out.println("not found");
			else {
				InputStream in = bundle.payloadInputStream;
				if (in == null)
					System.out.println("no payload");
				else {
					out = new FileOutputStream(dstpath);
					byte[] buf = new byte[4096];
					int n;
					while ((n = in.read(buf)) > 0)
						out.write(buf, 0, n);
					in.close();
					out.close();
					out = null;
				}
				System.out.println(
						(bundle.rowId == null ? "" : "_rowId=" + bundle.rowId + "\n") +
						(bundle.insertTime == null ? "" : "_insertTime=" + bundle.insertTime + "\n") +
						(bundle.author == null ? "" : "_author=" + bundle.author + "\n") +
						(bundle.secret == null ? "" : "_secret=" + bundle.secret + "\n") +
						manifestFields(bundle.manifest, "\n") + "\n"
					);
			}
		}
		catch (RhizomeException e) {
			System.out.println(e.toString());
		}
		finally {
			if (out != null)
				out.close();
		}
		System.exit(0);
	}

	static void rhizome_insert(	String author,
								String manifestPath,
								String payloadPath,
								String manifestoutpath,
								String payloadName,
								String secretHex)
		throws 	ServalDInterfaceException,
				IOException,
				InterruptedException,
				SubscriberId.InvalidHexException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		try {
			RhizomeIncompleteManifest manifest = new RhizomeIncompleteManifest();
			if (manifestPath != null && manifestPath.length() != 0)
				manifest.parseTextFormat(new FileInputStream(manifestPath));
			RhizomeInsertBundle bundle;
			SubscriberId authorSid = author == null || author.length() == 0 ? null : new SubscriberId(author);
			BundleSecret secret = secretHex == null || secretHex.length() == 0 ? null : new BundleSecret(secretHex);
			if (payloadName == null || payloadName.length() == 0)
				payloadName = new File(payloadPath).getName();
			if (payloadPath == null || payloadPath.length() == 0)
				bundle = client.rhizomeInsert(authorSid, manifest, secret);
			else
				bundle = client.rhizomeInsert(authorSid, manifest, secret, new FileInputStream(payloadPath), payloadName);
			System.out.println(
					"_status=" + bundle.status + "\n" +
					(bundle.rowId == null ? "" : "_rowId=" + bundle.rowId + "\n") +
					(bundle.insertTime == null ? "" : "_insertTime=" + bundle.insertTime + "\n") +
					(bundle.author == null ? "" : "_author=" + bundle.author + "\n") +
					(bundle.secret == null ? "" : "_secret=" + bundle.secret + "\n") +
					manifestFields(bundle.manifest, "\n") + "\n"
				);
			if (manifestoutpath != null && manifestoutpath.length() != 0) {
				FileOutputStream out = new FileOutputStream(manifestoutpath);
				out.write(bundle.manifestText());
				out.close();
			}
		}
		catch (RhizomeManifestParseException e) {
			System.out.println(e.toString());
		}
		catch (RhizomeException e) {
			System.out.println(e.toString());
		}
		System.exit(0);
	}

	public static void main(String... args)
	{
		if (args.length < 1)
			return;
		String methodName = args[0];
		try {
			if (methodName.equals("rhizome-list"))
				rhizome_list();
			else if (methodName.equals("rhizome-manifest"))
				rhizome_manifest(new BundleId(args[1]), args[2]);
			else if (methodName.equals("rhizome-payload-raw"))
				rhizome_payload_raw(new BundleId(args[1]), args[2]);
			else if (methodName.equals("rhizome-payload-decrypted"))
				rhizome_payload_decrypted(new BundleId(args[1]), args[2]);
			else if (methodName.equals("rhizome-insert"))
				rhizome_insert(	args[1], // author SID
								args[2], // manifest path
								args.length > 3 ? args[3] : null, // payload path
								args.length > 4 ? args[4] : null, // manifest out path
								args.length > 5 ? args[5] : null, // payload name
								args.length > 6 ? args[6] : null  // bundle secret
							  );
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
