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

package org.servalproject.servaldna.meshms;

import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

public class MeshMSConversation {

	public final int _rowNumber;
	public final int _id;
	public final Subscriber me;
	@Deprecated
	public final SubscriberId mySid;
	public final Subscriber them;
	@Deprecated
	public final SubscriberId theirSid;
	public final boolean isRead;
	public final long lastMessageOffset;
	public final long readOffset;

	protected MeshMSConversation(int rowNumber, int _id, Subscriber me, Subscriber them, boolean read, long last_message_offset, long read_offset)
	{
		this._rowNumber = rowNumber;
		this._id = _id;
		this.me = me;
		this.mySid = me.sid;
		this.them = them;
		this.theirSid = them.sid;
		this.isRead = read;
		this.lastMessageOffset = last_message_offset;
		this.readOffset = read_offset;
	}

	public int readHashCode() {
		int result = me.hashCode();
		result = 31 * result + them.hashCode();
		result = 31 * result + (int) (lastMessageOffset ^ (lastMessageOffset >>> 32));
		return result;
	}
}
