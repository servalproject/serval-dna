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

package org.servalproject.servaldna;

import java.io.IOException;

public class MdpDnaLookup extends AbstractMdpProtocol<ServalDCommand.LookupResult> {

	public MdpDnaLookup(ChannelSelector selector, int loopbackMdpPort, AsyncResult<ServalDCommand.LookupResult> results) throws IOException {
		super(selector, loopbackMdpPort, results);
	}

	public void sendRequest(SubscriberId destination, String did) throws IOException {
		MdpPacket request = new MdpPacket();
		if (destination.isBroadcast())
			request.setFlags(MdpPacket.MDP_FLAG_NO_CRYPT);
		request.setRemoteSid(destination);
		request.setRemotePort(MdpPacket.MDP_PORT_DNALOOKUP);
		request.payload.put(did.getBytes());
		request.payload.put((byte)0);
		request.payload.flip();
		socket.send(request);
	}

	@Override
	protected void parse(MdpPacket response) {
		try {
			byte bytes[] = new byte[response.payload.remaining()];
			response.payload.get(bytes);
			String resultString = new String(bytes);
			String fields[] = resultString.split("\\|");
			if (fields.length < 2)
				throw new IOException("Expected at least 2 result fields, got \""+resultString+"\"");
			ServalDCommand.LookupResult result = new ServalDCommand.LookupResult();
			result.subscriberId = new SubscriberId(fields[0]);
			result.uri = fields[1];
			result.did = (fields.length>2)?fields[2]:"";
			result.name = (fields.length>3)?fields[3]:"";
			results.result(result);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (AbstractId.InvalidHexException e) {
			e.printStackTrace();
		}
	}
}
