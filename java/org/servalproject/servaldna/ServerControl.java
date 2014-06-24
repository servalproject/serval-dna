package org.servalproject.servaldna;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by jeremy on 20/06/14.
 */
public class ServerControl {
	private String instancePath;
	private final String execPath;
	private int loopbackMdpPort;
	private int httpPort=0;
	private int pid;
	private static final String restfulUsername="ServalDClient";
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

	private void setStatus(ServalDCommand.Status result){
		loopbackMdpPort = result.mdpInetPort;
		pid = result.pid;
		httpPort = result.httpPort;
		instancePath = result.instancePath;
	}

	private void clearStatus(){
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

	public boolean isRunning() throws ServalDFailureException {
		ServalDCommand.Status s = ServalDCommand.serverStatus();

		if (s.status.equals("running")) {
			setStatus(s);
		}else{
			clearStatus();
		}
		return pid!=0;
	}

	public MdpServiceLookup getMdpServiceLookup(ChannelSelector selector, AsyncResult<MdpServiceLookup.ServiceResult> results) throws ServalDInterfaceException, IOException {
		if (!isRunning())
			throw new ServalDInterfaceException("server is not running");
		return new MdpServiceLookup(selector, this.loopbackMdpPort, results);
	}

	public MdpDnaLookup getMdpDnaLookup(ChannelSelector selector, AsyncResult<ServalDCommand.LookupResult> results) throws ServalDInterfaceException, IOException {
		if (!isRunning())
			throw new ServalDInterfaceException("server is not running");
		return new MdpDnaLookup(selector, this.loopbackMdpPort, results);
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
			String restfulPassword = ServalDCommand.getConfigItem("rhizome.api.restful.users." + restfulUsername + ".password");
			if (restfulPassword == null) {
				restfulPassword = new BigInteger(130, new SecureRandom()).toString(32);
				ServalDCommand.configActions(
						ServalDCommand.ConfigAction.set, "rhizome.api.restful.users." + restfulUsername + ".password", restfulPassword,
						ServalDCommand.ConfigAction.sync
				);
			}
			client = new ServalDClient(this.httpPort, restfulUsername, restfulPassword);
		}
		return client;
	}
}
