package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;

/**
 * Created by jeremy on 20/02/14.
 */
public class ChannelSelector {

	public static abstract class Handler{
		public abstract SelectableChannel getChannel();
		public abstract int getInterest();
		public void read(){};
		public void write(){};
		public void accept(){};
		public void connect(){};
	}

	private Runnable selectorThread = new Runnable(){
		@Override
		public void run() {
			try {
				while(true){
					if (registerHandler!=null || unregisterHandler!=null){
						synchronized (ChannelSelector.this){
							try {
								if (registerHandler!=null){
									SelectableChannel channel = registerHandler.getChannel();
									channel.configureBlocking(false);
									channel.register(selector, registerHandler.getInterest(), registerHandler);
								}
								if (unregisterHandler!=null){
									SelectableChannel channel = unregisterHandler.getChannel();
									channel.keyFor(selector).cancel();
									// force the cancelled key to be removed now
									selector.selectNow();
								}
							}catch (IOException e){
								e.printStackTrace();
								registerException = e;
							}catch (Throwable e){
								e.printStackTrace();
								registerException = new IOException(e.getMessage());
								registerException.initCause(e);
							}
							unregisterHandler = null;
							registerHandler=null;
							ChannelSelector.this.notify();
						}
					}
					if (selector.keys().isEmpty())
						break;

					if (selector.selectedKeys().isEmpty())
						selector.select();

					Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
					while(keys.hasNext()){
						SelectionKey key = keys.next();
						Handler h = (Handler)key.attachment();
						if (key.isValid()){
							if (key.isReadable())
								h.read();
							if (key.isWritable())
								h.write();
							if (key.isAcceptable())
								h.accept();
							if (key.isConnectable())
								h.connect();
						}
						keys.remove();
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			running = false;
		}
	};
	private boolean running = false;
	private final Selector selector;

	private Handler registerHandler;
	private Handler unregisterHandler;
	private IOException registerException;

	public ChannelSelector() throws IOException {
		selector = Selector.open();
	}

	public synchronized void unregister(Handler handler) throws IOException {
		// since we have to worry about thread synchronization,
		// pass the channel over to the selectorThread and only register it when we aren't blocking.
		if (running){
			unregisterHandler = handler;
			selector.wakeup();
			try {
				this.wait();
			} catch (InterruptedException e) {
			}
		}
		IOException e = registerException;
		registerException=null;
		if (e!=null)
			throw e;
	}

	public synchronized void register(Handler handler) throws IOException {
		// since we have to worry about thread synchronization,
		// pass the channel over to the selectorThread and only register it when we aren't blocking.
		registerHandler = handler;
		if (!running){
			running=true;
			new Thread(selectorThread).start();
		}
		selector.wakeup();
		try {
			this.wait();
		} catch (InterruptedException e) {
		}
		IOException e = registerException;
		registerException=null;
		if (e!=null)
			throw e;
	}
}
