package org.servalproject.servaldna;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;

/**
 * Created by jeremy on 17/02/14.
 */
public class MdpSocket{
	private DatagramChannel channel;
	private SubscriberId sid;
	private int port;

	private static final InetAddress loopback;
	public static int loopbackMdpPort =0;
	static {
		InetAddress local=null;
		try {
			local = Inet4Address.getByAddress(new byte[]{127, 0, 0, 1});
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		loopback = local;
	}

	public MdpSocket() throws IOException {
		this(SubscriberId.ANY, 0);
	}
	public MdpSocket(int port) throws IOException {
		this(SubscriberId.ANY, port);
	}
	public MdpSocket(SubscriberId sid, int port) throws IOException {
		if (loopbackMdpPort==0)
			throw new IOException("Loopback MDP port has not been set");
		channel = DatagramChannel.open();
		channel.connect(new InetSocketAddress(loopback, loopbackMdpPort));
		MdpPacket packet = new MdpPacket();
		packet.setLocalSid(sid);
		packet.setLocalPort(port);
		packet.setFlags(MdpPacket.MDP_FLAG_BIND);
		packet.payload.flip();
		packet.send(channel);
		receive(packet);
		try {
			this.sid = packet.getLocalSid();
		} catch (AbstractId.InvalidBinaryException e) {
			throw new MdpError(e);
		}
		this.port = packet.getLocalPort();
	}

	public SelectableChannel getChannel(){
		return channel;
	}

	public void send(MdpPacket packet) throws IOException {
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
		try {
			MdpPacket p = new MdpPacket();
			p.payload.flip();
			p.setFlags(MdpPacket.MDP_FLAG_CLOSE);
			send(p);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			channel.close();
		} catch (IOException e) {
			e.printStackTrace();
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
