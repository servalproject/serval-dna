package org.servalproject.servald;

import java.util.List;
import java.util.LinkedList;

class ServalD
{
	int status;
	List<String> outv;

	public ServalD()
	{
		System.loadLibrary("servald");
	}

	public native int rawCommand(List<String> outv, String... args);

	public void command(String... args)
	{
		this.outv = new LinkedList<String>();
		this.status = this.rawCommand(this.outv, args);
	}

	public static void main(String[] args)
	{
		ServalD servald = new ServalD();
		servald.command(args);
		for (String s: servald.outv) {
			System.out.println(s);
		}
		System.exit(servald.status);
	}
}
