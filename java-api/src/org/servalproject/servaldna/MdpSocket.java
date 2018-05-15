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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;

public class MdpSocket{
	private DatagramChannel channel = null;
	private SubscriberId sid = null;
	private int port;

	private static final InetAddress loopback;
	private final int loopbackMdpPort;
	static {
		InetAddress local=null;
		try {
			// can't trust Inet4Address.getLocalHost() as some implementations can fail to resolve the name "loopback"
			local = Inet4Address.getByAddress(new byte[]{127, 0, 0, 1});
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		loopback = local;
	}

	/* Create an unbound socket, may be used for other information requests before binding */
	public MdpSocket(int loopbackMdpPort) throws IOException {
		this.loopbackMdpPort = loopbackMdpPort;
	}
	public MdpSocket(int loopbackMdpPort, int port) throws IOException {
		this(loopbackMdpPort, SubscriberId.ANY, port);
	}
	public MdpSocket(int loopbackMdpPort, SubscriberId sid, int port) throws IOException {
		this(loopbackMdpPort);
		bind(sid, port);
	}

	public void bind() throws IOException {
		bind(SubscriberId.ANY, 0);
	}
	public void bind(int port) throws IOException {
		bind(SubscriberId.ANY, port);
	}
	public synchronized void bind(SubscriberId sid, int port) throws IOException {
		if (sid==null)
			throw new NullPointerException();
		if (sid.equals(this.sid) && this.port == port)
			return;
		if (this.sid!=null)
			throw new IOException("Socket is already bound");
		getChannel();
		if (!channel.isBlocking())
			throw new IOException("Cannot bind a non-blocking socket");
		MdpPacket packet = new MdpPacket();
		packet.setLocalSid(sid);
		packet.setLocalPort(port);
		packet.setFlags(MdpPacket.MDP_FLAG_BIND);
		packet.payload.flip();
		packet.send(channel);
		channel.socket().setSoTimeout(5000);
		// should throw MdpError on bind failures
		receive(packet);
		if (sid.isBroadcast()){
			this.sid = sid;
		}else{
			try {
				this.sid = packet.getLocalSid();
			} catch (AbstractId.InvalidBinaryException e) {
				e.printStackTrace();
				throw new MdpError(e);
			}
		}
		this.port = packet.getLocalPort();
	}

	public void rebind() throws IOException{
		if (this.sid==null)
			return;
		SubscriberId sid = this.sid;
		this.sid=null;
		bind(sid, this.port);
	}

	public SelectableChannel getChannel() throws IOException {
		if (channel == null){
			if (loopbackMdpPort==0)
				throw new IOException("Loopback MDP port has not been set");
			channel = DatagramChannel.open();
			channel.connect(new InetSocketAddress(loopback, loopbackMdpPort));
		}
		return channel;
	}

	public void send(MdpPacket packet) throws IOException {
		if (sid==null)
			bind(SubscriberId.ANY, 0);
		if (!this.sid.isBroadcast())
			packet.setLocalSid(this.sid);
		packet.setLocalPort(this.port);
		packet.send(channel);
	}

	public void receive(MdpPacket packet) throws IOException {
		packet.receive(channel);
		if ((packet.getFlags() & MdpPacket.MDP_FLAG_ERROR)!=0)
			throw new MdpError("Unspecified error reported by server");
	}

	public void close() {
		if (sid!=null){
			try {
				MdpPacket p = new MdpPacket();
				p.payload.flip();
				p.setFlags(MdpPacket.MDP_FLAG_CLOSE);
				send(p);
			} catch (IOException e) {
				// ignore errors due to servald stopping.
				e.printStackTrace();
			}
			sid = null;
		}
		if (channel!=null){
			try {
				channel.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static class MdpError extends IOException{
		public MdpError(String msg){
			super(msg);
		}
		public MdpError(String msg, Throwable cause){
			super(msg);
			this.initCause(cause);
		}
		public MdpError(Throwable cause){
			super();
			this.initCause(cause);
		}
	}
}
