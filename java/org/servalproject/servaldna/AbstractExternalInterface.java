package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;

/**
 * Created by jeremy on 8/05/14.
 */
public abstract class AbstractExternalInterface  extends ChannelSelector.Handler {
	private final ChannelSelector selector;
	protected final MdpSocket socket;

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
	}

	public void down() throws IOException {
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
