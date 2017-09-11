/**
 * Copyright (C) 2016 Flinders University
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
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;

public abstract class AbstractMdpProtocol<T>  extends ChannelSelector.Handler {
	private final ChannelSelector selector;
	protected final MdpSocket socket;
	protected final AsyncResult<T> results;

	public AbstractMdpProtocol(ChannelSelector selector, int loopbackMdpPort, AsyncResult<T> results) throws IOException {
		this(selector, loopbackMdpPort, results, SubscriberId.ANY, 0);
	}
	public AbstractMdpProtocol(ChannelSelector selector, int loopbackMdpPort, AsyncResult<T> results, int port) throws IOException {
		this(selector, loopbackMdpPort, results, SubscriberId.ANY, port);
	}
	public AbstractMdpProtocol(ChannelSelector selector, int loopbackMdpPort, AsyncResult<T> results, SubscriberId sid, int port) throws IOException {
		this.socket = new MdpSocket(loopbackMdpPort);
		socket.bind(sid, port);
		this.selector = selector;
		this.results = results;
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

	public void rebind() throws IOException {
		selector.unregister(this);
		try{
			socket.rebind();
		}finally{
			selector.register(this);
		}
	}

	protected abstract void parse(MdpPacket response);

	@Override
	public void read() throws IOException  {
		MdpPacket response = new MdpPacket();
		socket.receive(response);
		parse(response);
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
