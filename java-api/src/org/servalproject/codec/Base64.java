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

	public static final char[] SYMBOLS;
	public static final String charSet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static{
		char chars[] = new char[64];
		for (int i=0;i<chars.length;i++)
			chars[i]=charSet.charAt(i);
		SYMBOLS=chars;
	};

	public static String encode(byte[] binary)
	{
		StringBuilder sb = new StringBuilder();
		int place = 0;
		byte buf = 0;
		for (byte b: binary) {
			int val = b&0xFF;
			switch (place++) {
			case 0:
				sb.append(SYMBOLS[val >>> 2]);
				buf = (byte)((val << 4) & 0x3f);
				break;
			case 1:
				sb.append(SYMBOLS[(val >>> 4) | buf]);
				buf = (byte)((val << 2) & 0x3f);
				break;
			case 2:
				sb.append(SYMBOLS[(val >>> 6) | buf]);
				sb.append(SYMBOLS[val & 0x3f]);
				place = 0;
				break;
			}
		}
		if (place != 0)
			sb.append(SYMBOLS[buf]);
		switch (place) {
		case 1:
			sb.append('=');
		case 2:
			sb.append('=');
		}
		return sb.toString();
	}

	public static byte[] decode(String value)
	{
		int strlen = value.length();
		if (value.endsWith("=="))
			strlen-=2;
		else if (value.endsWith("="))
			strlen--;

		int len = (strlen+3)/4 * 3;
		switch(strlen%4){
			case 0:
				break;
			case 1:
			case 2:
				len -=2;
				break;
			case 3:
				len --;
				break;
		}

		byte ret[] = new byte[len];
		int pos=0;
		for (int i=0;i<strlen;i++){
			if (value.charAt(i)=='=')
				break;
			int val = charSet.indexOf(value.charAt(i));
			if (val<0)
				return null;
			switch(i%4){
				case 0:
					ret[pos]    = (byte) (val<<2);
					break;
				case 1:
					ret[pos++] |= (byte) ((val>>4)&0x03);
					if (pos>=ret.length) break;
					ret[pos]    = (byte) (val<<4);
					break;
				case 2:
					ret[pos++] |= (byte) ((val>>2)&0x0F);
					if (pos>=ret.length) break;
					ret[pos]    = (byte) (val<<6);
					break;
				case 3:
					ret[pos++] |= (byte) (val & 0x3f);
					break;
			}
		}
		return ret;
	}
}
