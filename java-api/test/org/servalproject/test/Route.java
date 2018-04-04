/**
 * Copyright (C) 2015 Serval Project Inc.
 * Copyright (C) 2018 Flinders University
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
import org.servalproject.servaldna.route.RouteIdentityList;
import org.servalproject.servaldna.route.RouteIdentity;

public class Route {

	static void route_list() throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		RouteIdentityList list = null;
		try {
			list = client.routeListIdentities();
			RouteIdentity id;
			while ((id = list.nextIdentity()) != null) {
				System.out.println("sid=" + id.sid +
								   ", did=" + id.did +
								   ", name=" + id.name +
								   ", isSelf=" + id.isSelf +
								   ", hopCount=" + id.hopCount +
								   ", reachableBroadcast=" + id.reachableBroadcast +
								   ", reachableUnicast=" + id.reachableUnicast +
								   ", reachableIndirect=" + id.reachableIndirect
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
			if (methodName.equals("list-all"))
				route_list();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
