package org.servalproject.servaldna.rhizome;

/**
 * Created by jeremy on 23/05/17.
 */
public class RhizomeImportStatus {
	public final RhizomeBundleStatus bundleStatus;
	public final RhizomePayloadStatus payloadStatus;

	RhizomeImportStatus(RhizomeBundleStatus bundleStatus, RhizomePayloadStatus payloadStatus) {
		this.bundleStatus = bundleStatus;
		this.payloadStatus = payloadStatus;
	}
}
