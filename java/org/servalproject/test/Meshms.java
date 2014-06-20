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

import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServerControl;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.meshms.MeshMSConversation;
import org.servalproject.servaldna.meshms.MeshMSConversationList;
import org.servalproject.servaldna.meshms.MeshMSException;
import org.servalproject.servaldna.meshms.MeshMSMessage;
import org.servalproject.servaldna.meshms.MeshMSMessageList;

import java.io.IOException;

public class Meshms {

	static void meshms_list_conversations(SubscriberId sid) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		MeshMSConversationList list = null;
		try {
			list = client.meshmsListConversations(sid);
			MeshMSConversation conv;
			while ((conv = list.nextConversation()) != null) {
				System.out.println(
					"_id=" + conv._id +
					", my_sid=" + conv.mySid +
					", their_sid=" + conv.theirSid +
					", read=" + conv.isRead +
					", last_message=" + conv.lastMessageOffset +
					", read_offset=" + conv.readOffset
				);
			}
		}
		catch (MeshMSException e) {
			System.out.println(e.toString());
		}
		finally {
			if (list != null)
				list.close();
		}
		System.exit(0);
	}

	static void meshms_list_messages(SubscriberId sid1, SubscriberId sid2) throws ServalDInterfaceException, IOException, InterruptedException
	{
		ServalDClient client = new ServerControl().getRestfulClient();
		MeshMSMessageList list = null;
		try {
			list = client.meshmsListMessages(sid1, sid2);
			System.out.println("read_offset=" + list.getReadOffset());
			System.out.println("latest_ack_offset=" + list.getLatestAckOffset());
			MeshMSMessage msg;
			while ((msg = list.nextMessage()) != null) {
				System.out.println("type=" + msg.type
							   + ", my_sid=" + msg.mySid
							   + ", their_sid=" + msg.theirSid
							   + ", offset=" + msg.offset
							   + ", token=" + msg.token
							   + ", text=" + (msg.text == null ? null : msg.text.replace('\n', '.').replace(' ', '.'))
							   + ", delivered=" + msg.isDelivered
							   + ", read=" + msg.isRead
							   + ", ack_offset=" + msg.ackOffset
							);
			}
		}
		catch (MeshMSException e) {
			System.out.println(e.toString());
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
			if (methodName.equals("meshms-list-conversations"))
				meshms_list_conversations(new SubscriberId(args[1]));
			else if (methodName.equals("meshms-list-messages"))
				meshms_list_messages(new SubscriberId(args[1]), new SubscriberId(args[2]));
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
	}
}
