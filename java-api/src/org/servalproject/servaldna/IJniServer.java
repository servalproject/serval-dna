package org.servalproject.servaldna;

/**
 * Created by jeremy on 4/05/15.
 */
public interface IJniServer {
	long aboutToWait(long now, long nextRun, long nextWake);
	void wokeUp();
	void started(String instancePath, int pid, int mdpPort, int httpPort);
}
