/**
 * Copyright (C) 2015 Serval Project Inc.
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
import org.servalproject.servaldna.ServalDNotImplementedException;
import org.servalproject.servaldna.ServerControl;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.BundleSecret;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.keyring.KeyringIdentityList;
import org.servalproject.servaldna.keyring.KeyringIdentity;

public class Keyring {

	static void keyring_list(String pin) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		KeyringIdentityList list = null;
		try {
			list = client.keyringListIdentities(pin);
			KeyringIdentity id;
			while ((id = list.nextIdentity()) != null) {
				System.out.println("sid=" + id.sid +
								   ", did=" + id.did +
								   ", name=" + id.name
					);
			}
		}
		finally {
			if (list != null)
				list.close();
		}
		System.exit(0);
	}

	static void set(SubscriberId sid, String did, String name, String pin) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		KeyringIdentity id = client.keyringSetDidName(sid, did, name, pin);
		System.out.println("sid=" + id.sid +
						   ", did=" + id.did +
						   ", name=" + id.name
			);
		System.exit(0);
	}

	static void add(String did, String name, String pin) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		KeyringIdentity id = client.keyringAdd(did, name, pin);
		System.out.println("sid=" + id.sid +
						   ", did=" + id.did +
						   ", name=" + id.name
			);
		System.exit(0);
	}

	static void remove(SubscriberId sid, String pin) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		KeyringIdentity id = client.keyringRemove(sid, pin);
		System.out.println("sid=" + id.sid +
						   ", did=" + id.did +
						   ", name=" + id.name
			);
		System.exit(0);
	}

	public static void main(String... args)
	{
		if (args.length < 1)
			return;
		String methodName = args[0];
		try {
			if (methodName.equals("list-identities"))
				keyring_list(args.length >= 2 ? args[1] : null);
			else if (methodName.equals("set"))
				set(new SubscriberId(args[1]), args[2], args[3], args.length >= 5 ? args[4] : null);
			else if (methodName.equals("add"))
				add(args[1], args[2], args.length >= 4 ? args[3] : null);
			else if (methodName.equals("remove"))
				remove(new SubscriberId(args[1]), args.length >= 3 ? args[2] : null);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
