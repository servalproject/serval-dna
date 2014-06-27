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
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServerControl;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.rhizome.RhizomeBundle;
import org.servalproject.servaldna.rhizome.RhizomeBundleList;

public class Rhizome {

	static void rhizome_list() throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		RhizomeBundleList list = null;
		try {
			list = client.rhizomeListBundles();
			RhizomeBundle bundle;
			while ((bundle = list.nextBundle()) != null) {
				System.out.println(
					"_id=" + bundle._id +
					", .token=" + bundle._token +
					", service=" + bundle.service +
					", id=" + bundle.id +
					", version=" + bundle.version +
					", date=" + bundle.date +
					", .inserttime=" + bundle._inserttime +
					", .author=" + bundle._author +
					", .fromhere=" + bundle._fromhere +
					", filesize=" + bundle.filesize +
					", filehash=" + bundle.filehash +
					", sender=" + bundle.sender +
					", recipient=" + bundle.recipient +
					", name=" + bundle.name
				);
			}
		}
		finally {
			if (list != null)
				list.close();
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
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
