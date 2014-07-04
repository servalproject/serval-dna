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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServerControl;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.rhizome.RhizomeManifest;
import org.servalproject.servaldna.rhizome.RhizomeListBundle;
import org.servalproject.servaldna.rhizome.RhizomeBundleList;
import org.servalproject.servaldna.rhizome.RhizomeManifestBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadRawBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadBundle;
import org.servalproject.servaldna.rhizome.RhizomeException;

public class Rhizome {

	static String manifestFields(RhizomeManifest manifest, String sep)
	{
		return	"id=" + manifest.id + sep +
				"version=" + manifest.version + sep +
				"filesize=" + manifest.filesize + sep +
				"filehash=" + manifest.filehash + sep +
				"sender=" + manifest.sender + sep +
				"recipient=" + manifest.recipient + sep +
				"date=" + manifest.date + sep +
				"service=" + manifest.service + sep +
				"name=" + manifest.name + sep +
				"BK=" + manifest.BK;
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
						"_rowId=" + bundle.rowId +
						", _token=" + bundle.token +
						", _insertTime=" + bundle.insertTime +
						", _author=" + bundle.author +
						", _fromHere=" + bundle.fromHere +
						", " + manifestFields(bundle.manifest, ", ")
					);
			}
		}
		catch (RhizomeException e) {
			System.out.println(e.toString());
		}
		finally {
			if (list != null)
				list.close();
		}
		System.exit(0);
	}

	static void rhizome_manifest(BundleId bid, String dstpath) throws ServalDInterfaceException, IOException, InterruptedException
	{
		try {
			ServalDClient client = new ServerControl().getRestfulClient();
			RhizomeManifestBundle bundle = client.rhizomeManifest(bid);
			if (bundle == null)
				System.out.println("not found");
			else {
				System.out.println(
						"_insertTime=" + bundle.insertTime + "\n" +
						"_author=" + bundle.author + "\n" +
						"_secret=" + bundle.secret + "\n" +
						manifestFields(bundle.manifest, "\n") + "\n"
					);
				FileOutputStream out = new FileOutputStream(dstpath);
				out.write(bundle.manifestText());
				out.close();
			}
		}
		catch (RhizomeException e) {
			System.out.println(e.toString());
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
						"_insertTime=" + bundle.insertTime + "\n" +
						"_author=" + bundle.author + "\n" +
						"_secret=" + bundle.secret + "\n" +
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
						"_insertTime=" + bundle.insertTime + "\n" +
						"_author=" + bundle.author + "\n" +
						"_secret=" + bundle.secret + "\n" +
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
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
