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
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Properties;

public class MdpServiceLookup extends AbstractMdpProtocol<MdpServiceLookup.ServiceResult> {

	public static class ServiceResult extends Properties {
		public final SubscriberId subscriberId;
		public ServiceResult(SubscriberId subscriberId){
			this.subscriberId = subscriberId;
		}

		public String toString(){
			return "ServiceResult{subscriberId="+subscriberId+", "+super.toString()+"}";
		}
	}

	public MdpServiceLookup(ChannelSelector selector, int loopbackMdpPort, AsyncResult<ServiceResult> results) throws IOException {
		super(selector, loopbackMdpPort, results);
	}

	public void sendRequest(SubscriberId destination, String pattern) throws IOException {
		MdpPacket request = new MdpPacket();
		if (destination.isBroadcast())
			request.setFlags(MdpPacket.MDP_FLAG_NO_CRYPT);
		request.setRemoteSid(destination);
		request.setRemotePort(MdpPacket.MDP_PORT_SERVICE_DISCOVERY);
		request.payload.put(pattern.getBytes());
		request.payload.put((byte)0);
		request.payload.flip();
		socket.send(request);
	}

	public static class BuffStream extends InputStream{
		private final ByteBuffer buff;
		public BuffStream(ByteBuffer buff){
			this.buff = buff;
		}

		@Override
		public boolean markSupported() {
			return true;
		}

		@Override
		public int read() throws IOException {
			if (!buff.hasRemaining())
				return -1;
			return buff.get()&0xFF;
		}

		@Override
		public void mark(int readLimit){
			buff.mark();
		}

		@Override
		public void reset() throws IOException {
			buff.rewind();
		}

		@Override
		public void close() throws IOException {
			// noop
		}

		@Override
		public int read(byte[] dst, int dstOffset, int charCount) throws IOException {
			if (!buff.hasRemaining())
				return -1;
			if (charCount > buff.remaining())
				charCount = buff.remaining();
			buff.get(dst, dstOffset, charCount);
			return charCount;
		}
	}

	@Override
	protected void parse(MdpPacket response) {
		try {
			ServiceResult result = new ServiceResult(response.getRemoteSid());
			result.load(new BuffStream(response.payload));
			results.result(result);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (AbstractId.InvalidBinaryException e) {
			e.printStackTrace();
		}
	}
}
