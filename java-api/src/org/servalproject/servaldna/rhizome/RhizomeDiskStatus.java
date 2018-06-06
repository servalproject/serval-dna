package org.servalproject.servaldna.rhizome;

import org.servalproject.json.JsonField;
import org.servalproject.json.JsonObjectHelper;

import java.util.Map;
import java.util.UUID;

public class RhizomeDiskStatus {
	public final String rhizomeDir;
	public final UUID rhizomeUUID;
	public final long fileCount;
	public final long internalBytes;
	public final long externalBytes;
	public final long overheadBytes;
	public final long usedBytes;
	public final long availableBytes;
	public final long reclaimableBytes;
	public final long filesystemBytes;
	public final long filesystemFreeBytes;

	public RhizomeDiskStatus(
			String rhizomeDir,
			UUID rhizomeUUID,
			long fileCount,
			long internalBytes,
			long externalBytes,
			long overheadBytes,
			long usedBytes,
			long availableBytes,
			long reclaimableBytes,
			long filesystemBytes,
			long filesystemFreeBytes
	) {
		this.rhizomeDir = rhizomeDir;
		this.rhizomeUUID = rhizomeUUID;
		this.fileCount = fileCount;
		this.internalBytes = internalBytes;
		this.externalBytes = externalBytes;
		this.overheadBytes = overheadBytes;
		this.usedBytes = usedBytes;
		this.availableBytes = availableBytes;
		this.reclaimableBytes = reclaimableBytes;
		this.filesystemBytes = filesystemBytes;
		this.filesystemFreeBytes = filesystemFreeBytes;
	}

	@Override
	public String toString() {
		return "RhizomeDiskStatus{" +
				"rhizomeDir='" + rhizomeDir + '\'' +
				", rhizomeUUID=" + rhizomeUUID +
				", fileCount=" + fileCount +
				", internalBytes=" + internalBytes +
				", externalBytes=" + externalBytes +
				", overheadBytes=" + overheadBytes +
				", usedBytes=" + usedBytes +
				", availableBytes=" + availableBytes +
				", reclaimableBytes=" + reclaimableBytes +
				", filesystemBytes=" + filesystemBytes +
				", filesystemFreeBytes=" + filesystemFreeBytes +
				'}';
	}

	private static Map<String, JsonField> fields = JsonField.mapBuilder()
			.addField("rhizome_dir", true, JsonObjectHelper.StringFactory)
			.addField("rhizome_uuid", true, JsonObjectHelper.StringFactory)
			.addField("file_count", true, JsonObjectHelper.LongFactory)
			.addField("internal_bytes", true, JsonObjectHelper.LongFactory)
			.addField("external_bytes", true, JsonObjectHelper.LongFactory)
			.addField("overhead_bytes", true, JsonObjectHelper.LongFactory)
			.addField("used_bytes", true, JsonObjectHelper.LongFactory)
			.addField("available_bytes", true, JsonObjectHelper.LongFactory)
			.addField("reclaimable_bytes", true, JsonObjectHelper.LongFactory)
			.addField("filesystem_bytes", true, JsonObjectHelper.LongFactory)
			.addField("filesystem_free_bytes", true, JsonObjectHelper.LongFactory)
			.build();

	public static JsonObjectHelper.ObjectFactory<RhizomeDiskStatus> factory = new JsonObjectHelper.ObjectFactory<RhizomeDiskStatus>(fields) {
		@Override
		public RhizomeDiskStatus create(Map<String, Object> values) {
			return new RhizomeDiskStatus(
					(String)values.get("rhizome_dir"),
					UUID.fromString((String)values.get("rhizome_uuid")),
					(Long)values.get("file_count"),
					(Long)values.get("internal_bytes"),
					(Long)values.get("external_bytes"),
					(Long)values.get("overhead_bytes"),
					(Long)values.get("used_bytes"),
					(Long)values.get("available_bytes"),
					(Long)values.get("reclaimable_bytes"),
					(Long)values.get("filesystem_bytes"),
					(Long)values.get("filesystem_free_bytes")
			);
		}
	};
}
