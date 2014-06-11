/**
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

package org.servalproject.codec;

import java.lang.StringBuilder;

public class Base64 {

	public static final char[] SYMBOLS = {
		'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
		'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
		'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/',
		'='
	};

	public static String encode(byte[] binary)
	{
		StringBuilder sb = new StringBuilder();
		int place = 0;
		byte buf = 0;
		for (byte b: binary) {
			switch (place) {
			case 0:
				sb.append(SYMBOLS[b >>> 2]);
				buf = (byte)((b << 4) & 0x3f);
				place = 1;
				break;
			case 1:
				sb.append(SYMBOLS[(b >>> 4) | buf]);
				buf = (byte)((b << 2) & 0x3f);
				place = 2;
				break;
			case 2:
				sb.append(SYMBOLS[(b >>> 6) | buf]);
				sb.append(SYMBOLS[b & 0x3f]);
				place = 0;
				break;
			}
		}
		if (place != 0)
			sb.append(SYMBOLS[buf]);
		switch (place) {
		case 1:
			sb.append(SYMBOLS[64]);
		case 2:
			sb.append(SYMBOLS[64]);
		}
		return sb.toString();
	}

}
