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
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;

public class ChannelSelector {

	public static abstract class Handler{
		public abstract SelectableChannel getChannel() throws IOException;
		public abstract int getInterest();
		public void read() throws IOException {};
		public void write() throws IOException {};
		public void accept() throws IOException {};
		public void finishConnect() throws IOException {};
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
									channel.configureBlocking(true);
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
						try {
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
									h.finishConnect();

								SelectableChannel channel = h.getChannel();
								int i = h.getInterest() & channel.validOps();
								if (i == 0) {
									key.cancel();
									channel.configureBlocking(true);
								} else {
									key.interestOps(i);
								}
							}
						}catch (CancelledKeyException e){
							// ignore
						}catch(IOException e){
							e.printStackTrace();
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
