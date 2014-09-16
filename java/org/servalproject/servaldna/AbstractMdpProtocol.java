package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;

/**
 * Created by jeremy on 8/05/14.
 */
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
	public void read() {
		try {
			MdpPacket response = new MdpPacket();
			socket.receive(response);
			parse(response);
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
