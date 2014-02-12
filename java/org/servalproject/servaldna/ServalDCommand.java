/**
 * Copyright (C) 2011 The Serval Project
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

import java.util.LinkedList;

public class ServalDCommand
{
	private ServalDCommand(){
	}

	static
	{
		System.loadLibrary("servald");
	}

	/**
	 * Low-level JNI entry point into servald command line.
	 *
	 * @param results	Interface that will receive each value from the command
	 * @param args		The words to pass on the command line (ie, argv[1]...argv[n])
	 * @return			The servald exit status code (normally 0 indicates success)
	 */
	private static native int rawCommand(IJniResults results, String[] args)
			throws ServalDInterfaceError;

	/**
	 * Common entry point into servald command line.
	 *
	 * @param callback
	 *            Each result will be passed to callback.result(String)
	 *            immediately.
	 * @param args
	 *            The parameters as passed on the command line, eg: res =
	 *            servald.command("config", "set", "debug", "peers");
	 * @return The servald exit status code (normally0 indicates success)
	 */
	public static synchronized int command(final IJniResults callback, String... args)
			throws ServalDInterfaceError
	{
		return ServalDCommand.rawCommand(callback, args);
	}

	/**
	 * Common entry point into servald command line.
	 *
	 * @param args
	 *            The parameters as passed on the command line, eg: res =
	 *            servald.command("config", "set", "debug", "peers");
	 * @return An object containing the servald exit status code (normally0
	 *         indicates success) and zero or more output fields that it would
	 *         have sent to standard output if invoked via a shell command line.
	 */

	public static synchronized ServalDResult command(String... args)
			throws ServalDInterfaceError
	{
		LinkedList<byte[]> results = new LinkedList<byte[]>();
		int status = rawCommand(new JniResultsList(results), args);
		return new ServalDResult(args, status, results.toArray(new byte[results.size()][]));
	}


	public static void main(String[] args)
	{
		LinkedList<byte[]> outv = new LinkedList<byte[]>();
		IJniResults results = new JniResultsList(outv);
		int status = rawCommand(results, args);
		for (byte[] a: outv) {
			System.out.println(new String(a));
		}
		System.exit(status);
	}
}
