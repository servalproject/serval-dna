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

import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.ServalDInterfaceException;

public class MeshMSMessage {

	public enum Type {
		MESSAGE_SENT,
		MESSAGE_RECEIVED,
		ACK_RECEIVED
	};

	public final int _rowNumber;
	public final Type type;
	public final SubscriberId mySid;
	public final SubscriberId theirSid;
	public final long offset;
	public final String token;
	public final String text;
	public final boolean isDelivered;
	public final boolean isRead;
	public final Long timestamp;
	public final Long ackOffset;

	protected MeshMSMessage(int rowNumber,
							Type type,
							SubscriberId my_sid,
							SubscriberId their_sid,
							long offset,
							String token,
							String text,
							boolean delivered,
							boolean read,
							Long timestamp,
							Long ack_offset) throws ServalDInterfaceException
	{
		if (my_sid == null)
			throw new ServalDInterfaceException("my_sid is null");
		if (their_sid == null)
			throw new ServalDInterfaceException("their_sid is null");
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
		this.mySid = my_sid;
		this.theirSid = their_sid;
		this.offset = offset;
		this.token = token;
		this.text = text;
		this.isDelivered = delivered;
		this.isRead = read;
		this.timestamp = timestamp;
		this.ackOffset = ack_offset;
	}

	public long getId(){
		switch (type){
			default:
				return offset;
			case MESSAGE_RECEIVED:
				return -offset;
			case ACK_RECEIVED:
				return 0;
		}
	}
}
