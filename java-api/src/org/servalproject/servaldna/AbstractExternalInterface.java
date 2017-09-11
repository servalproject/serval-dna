/**
 * Copyright (C) 2014-2015 Serval Project Inc.
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
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;

public abstract class AbstractExternalInterface  extends ChannelSelector.Handler {
	private final ChannelSelector selector;
	protected final MdpSocket socket;
	private boolean isUp = false;

	public AbstractExternalInterface(ChannelSelector selector, int loopbackMdpPort) throws IOException {
		this.socket = new MdpSocket(loopbackMdpPort);

		this.selector = selector;
		selector.register(this);
	}

	public void close(){
		try {
			selector.unregister(this);
		} catch (IOException e) {
			e.printStackTrace();
		}
		socket.close();
	}

	private static final int MDP_INTERFACE=4;
	private static final int MDP_INTERFACE_UP=0;
	private static final int MDP_INTERFACE_DOWN=1;
	private static final int MDP_INTERFACE_RECV=2;

	public void up(String config) throws IOException {
		MdpPacket packet = new MdpPacket();
		packet.setRemotePort(MDP_INTERFACE);
		packet.payload.put((byte) MDP_INTERFACE_UP);
		packet.payload.put(config.getBytes());
		packet.payload.flip();
		packet.send((DatagramChannel)socket.getChannel());
		isUp = true;
	}

	public void down() throws IOException {
		isUp = false;
		MdpPacket packet = new MdpPacket();
		packet.setRemotePort(MDP_INTERFACE);
		packet.payload.put((byte) MDP_INTERFACE_DOWN);
		packet.payload.flip();
		packet.send((DatagramChannel) socket.getChannel());
	}

	public void receivedPacket(byte recvaddr[], byte recvbytes[]) throws IOException {
		receivedPacket(recvaddr, recvbytes, 0, recvbytes==null?0:recvbytes.length);
	}
	public void receivedPacket(byte recvaddr[], byte recvbytes[], int offset, int len) throws IOException {
		if (!isUp)
			return;

		MdpPacket packet = new MdpPacket();
		packet.setRemotePort(MDP_INTERFACE);
		packet.payload.put((byte) MDP_INTERFACE_RECV);
		packet.payload.put((byte) recvaddr.length);
		packet.payload.put(recvaddr);
		if (len>0)
			packet.payload.put(recvbytes, offset, len);
		packet.payload.flip();
		packet.send((DatagramChannel) socket.getChannel());
	}

	protected abstract void sendPacket(byte addr[], ByteBuffer payload);

	@Override
	public void read() {
		try {
			MdpPacket response = new MdpPacket();
			socket.receive(response);
			if (!isUp)
				return;
			int addrlen = response.payload.get() & 0xFF;
			byte addr[]=null;
			if (addrlen>0) {
				addr = new byte[addrlen];
				response.payload.get(addr);
			}
			sendPacket(addr, response.payload);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public SelectableChannel getChannel() throws IOException {
		return socket.getChannel();
	}

	@Override
	public int getInterest() {
		return SelectionKey.OP_READ;
	}
}
