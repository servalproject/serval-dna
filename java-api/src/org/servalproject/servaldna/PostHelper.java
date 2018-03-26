/**
 * Copyright (C) 2016-2017 Flinders University
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

import org.servalproject.servaldna.rhizome.RhizomeIncompleteManifest;
import org.servalproject.servaldna.rhizome.RhizomeManifest;
import org.servalproject.servaldna.rhizome.RhizomeManifestSizeException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

public class PostHelper {
    private HttpURLConnection conn;
    private String boundary;
    private OutputStream output;
    private PrintStream writer;

    public PostHelper(HttpURLConnection conn) {
        this.conn = conn;
        boundary = Long.toHexString(System.currentTimeMillis());
    }

    public void connect() throws IOException {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        // we try to set an expect header so we can gracefully deal with the server aborting early
        // however implementations don't seem to support it well and will throw a ProtocolException
        // if the server doesn't return a 100-Continue
        // Other implementations (like android), just strip the header.
        // Then if the server closes the connection early, throw some form of IOException
        conn.setRequestProperty("Expect", "100-continue");
        // If we don't set this, Java might try to re-use a connection that the server closed
        conn.setRequestProperty("Connection", "close");
        conn.setChunkedStreamingMode(0);
        conn.connect();
        output = conn.getOutputStream();
        output.flush();
        writer = new PrintStream(output, false, "UTF-8");
    }

    private void quoteString(StringBuilder sb, String unquoted)
    {
        if (unquoted == null) {
            sb.append("null");
            return;
        }
        sb.append('"');
        for (int i = 0; i < unquoted.length(); ++i) {
            char c = unquoted.charAt(i);
            if (c == '"' || c == '\\')
                sb.append('\\');
            sb.append(c);
        }
        sb.append('"');
    }

    protected void writeHeading(String name, String filename, ContentType type, String encoding)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("\r\n--").append(boundary).append("\r\n");
        sb.append("Content-Disposition: form-data; name=");
        quoteString(sb, name);
        if (filename!=null) {
            sb.append("; filename=");
            quoteString(sb, filename);
        }
        sb.append("\r\n");
        sb.append("Content-Type: ").append(type.toString()).append("\r\n");
        if (encoding!=null)
            sb.append("Content-Transfer-Encoding: ").append(encoding).append("\r\n");
        sb.append("\r\n");
        writer.print(sb.toString());
    }

    public void writeField(String name, String value){
        writeHeading(name, null, ContentType.textPlain, null);
        writer.print(value);
    }

    public void writeField(String name, AbstractId value){
        writeHeading(name, null, value.getMimeType(), null);
        writer.print(value.toHex());
    }

    public OutputStream beginFileField(String name, String filename){
        writeHeading(name, filename, ContentType.applicationOctetStream, "binary");
        writer.flush();
        return output;
    }

    public void writeField(String name, String filename, InputStream stream) throws IOException {
        beginFileField(name, filename);
        byte[] buffer = new byte[4096];
        int n;
        while ((n = stream.read(buffer)) > 0)
            output.write(buffer, 0, n);
    }

    public void writeField(String name, ContentType type, byte value[]) throws IOException {
        writeHeading(name, null, type, "binary");
        writer.flush();
        output.write(value);
    }

    public void writeField(String name, ContentType type, byte value[], int offset, int length) throws IOException {
        writeHeading(name, null, type, "binary");
        writer.flush();
        output.write(value, offset, length);
    }

    public void writeField(String name, RhizomeManifest manifest) throws IOException, RhizomeManifestSizeException {
        writeHeading(name, null, RhizomeManifest.MIME_TYPE, "binary");
        manifest.toTextFormat(writer);
    }

    public void writeField(String name, RhizomeIncompleteManifest manifest) throws IOException {
        writeHeading(name, null, RhizomeManifest.MIME_TYPE, "binary");
        manifest.toTextFormat(writer);
    }

    public void close() throws IOException {
        if (writer!=null) {
            writer.print("\r\n--" + boundary + "--\r\n");
            writer.flush();
            writer.close();
            writer=null;
        }
        if (output!=null) {
            output.close();
            output = null;
        }
    }
}
