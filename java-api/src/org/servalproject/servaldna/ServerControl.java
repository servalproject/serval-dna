/**
 * Copyright (C) 2016 Flinders University
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
import java.math.BigInteger;
import java.security.SecureRandom;

public class ServerControl {
	private String instancePath;
	private final String execPath;
	private int loopbackMdpPort;
	private int httpPort=0;
	private int pid;
	public static final String restfulUsername="ServalDClient";
	private ServalDClient client;

	public ServerControl(){
		this(null);
	}
	public ServerControl(String execPath){
		this.execPath = execPath;
	}

	public String getInstancePath(){
		return instancePath;
	}

	public String getExecPath() {
		return this.execPath;
	}

	public int getLoopbackMdpPort() {
		return loopbackMdpPort;
	}

	public int getPid() {
		return pid;
	}

	protected void setStatus(String instancePath, int pid, int mdpInetPort, int httpPort){
		this.instancePath = instancePath;
		this.pid = pid;
		this.loopbackMdpPort = mdpInetPort;
		this.httpPort = httpPort;
	}

	private void setStatus(ServalDCommand.Status result){
		loopbackMdpPort = result.mdpInetPort;
		pid = result.pid;
		httpPort = result.httpPort;
		instancePath = result.instancePath;
	}

	protected void clearStatus(){
		loopbackMdpPort = 0;
		pid = 0;
		httpPort = 0;
		client = null;
	}

	public void start() throws ServalDFailureException {
		if (execPath==null)
			setStatus(ServalDCommand.serverStart());
		else
			setStatus(ServalDCommand.serverStart(execPath));
	}

	public void stop() throws ServalDFailureException {
		try{
			ServalDCommand.serverStop();
		}finally{
			clearStatus();
		}
	}

	public void restart() throws ServalDFailureException {
		try {
			stop();
		} catch (ServalDFailureException e) {
			// ignore failures, at least we tried...
			e.printStackTrace();
		}
		start();
	}

	public boolean isRunning() {
		try {
			ServalDCommand.Status s = ServalDCommand.serverStatus();
			if (s.status.equals("running")) {
				setStatus(s);
				return pid!=0;
			}
		} catch (ServalDFailureException e) {
			// ignore
		}
		clearStatus();
		return pid!=0;
	}

	public MdpServiceLookup getMdpServiceLookup(ChannelSelector selector, AsyncResult<MdpServiceLookup.ServiceResult> results) throws ServalDInterfaceException, IOException {
		if (!isRunning())
			throw new ServalDInterfaceException("server is not running");
		return new MdpServiceLookup(selector, getLoopbackMdpPort(), results);
	}

	public MdpDnaLookup getMdpDnaLookup(ChannelSelector selector, AsyncResult<ServalDCommand.LookupResult> results) throws ServalDInterfaceException, IOException {
		if (!isRunning())
			throw new ServalDInterfaceException("server is not running");
		return new MdpDnaLookup(selector, getLoopbackMdpPort(), results);
	}

	public ServalDClient getRestfulClient() throws ServalDInterfaceException {
		if (!isRunning())
			throw new ServalDInterfaceException("server is not running");
		if (client==null) {
			/* TODO: replace the following username/password configuration with a better scheme
			 * (outside the scope of this API) that does not require any invocations of the JNI, and
			 * allows any application (user) on the local host to request authorisation to use the
			 * RESTful interface.  The authorisation must then be supplied to the restful client
			 * object before requests can be made.
			 */
			String restfulPassword = ServalDCommand.getConfigItem("api.restful.users." + restfulUsername + ".password");
			if (restfulPassword == null) {
				restfulPassword = new BigInteger(130, new SecureRandom()).toString(32);
				ServalDCommand.configActions(
						ServalDCommand.ConfigAction.set, "api.restful.users." + restfulUsername + ".password", restfulPassword,
						ServalDCommand.ConfigAction.sync
				);
			}
			client = new ServalDClient(this.httpPort, restfulUsername, restfulPassword);
		}
		return client;
	}
}
