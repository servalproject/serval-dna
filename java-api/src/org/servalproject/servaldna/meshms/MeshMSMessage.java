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
import org.servalproject.servaldna.ServalDInterfaceException;

import java.util.Date;

public class MeshMSMessage implements Comparable<MeshMSMessage>{

	public enum Type {
		MESSAGE_SENT,
		MESSAGE_RECEIVED,
		ACK_RECEIVED
	};

	public final int _rowNumber;
	public final Type type;
	public final Subscriber me;
	@Deprecated
	public final SubscriberId mySid;
	public final Subscriber them;
	@Deprecated
	public final SubscriberId theirSid;
	public final long myOffset;
	public final long theirOffset;
	public final String token;
	public final String text;
	public final boolean isDelivered;
	public final boolean isRead;
	public final Long timestamp;
	public final Date date;
	public final Long ackOffset;

	protected MeshMSMessage(int rowNumber,
							Type type,
							Subscriber me,
							Subscriber them,
							long myOffset,
							long theirOffset,
							String token,
							String text,
							boolean delivered,
							boolean read,
							Long timestamp,
							Long ack_offset) throws ServalDInterfaceException
	{
		if (me == null)
			throw new ServalDInterfaceException("me is null");
		if (them == null)
			throw new ServalDInterfaceException("them is null");
		if (type != Type.ACK_RECEIVED && text == null)
			throw new ServalDInterfaceException("text is null");
		if (token == null)
			throw new ServalDInterfaceException("token is null");
		if (type == Type.ACK_RECEIVED && ack_offset == null)
			throw new ServalDInterfaceException("ack_offset is null");
		if (type != Type.ACK_RECEIVED && timestamp == null)
			throw new ServalDInterfaceException("timestamp is null");
		this._rowNumber = rowNumber;
		this.type = type;
		this.me = me;
		this.mySid = me.sid;
		this.them = them;
		this.theirSid = them.sid;
		this.myOffset = myOffset;
		this.theirOffset = theirOffset;
		this.token = token;
		this.text = text;
		this.isDelivered = delivered;
		this.isRead = read;
		this.timestamp = timestamp;
		this.date = new Date((timestamp ==null?0:timestamp * 1000));
		this.ackOffset = ack_offset;
	}

	public long getId(){
		switch (type){
			default:
				return myOffset;
			case MESSAGE_RECEIVED:
				return -theirOffset;
			case ACK_RECEIVED:
				return 0;
		}
	}

	@Override
	public int compareTo(MeshMSMessage meshMSMessage) {
		if (this.myOffset < meshMSMessage.myOffset)
			return -1;
		if (this.myOffset > meshMSMessage.myOffset)
			return 1;
		if (this.theirOffset < meshMSMessage.theirOffset)
			return -1;
		if (this.theirOffset > meshMSMessage.theirOffset)
			return 1;
		return 0;
	}
}
