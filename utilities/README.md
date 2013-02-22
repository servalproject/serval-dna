Serval DNA Utilities
====================
[Serval Project][], February 2013

This directory contains utilities that accompany [Serval DNA][]:

 * [`rhizome_mirrord`][] is a Python 2.7 script that continuously extracts
   Rhizome bundles from a local Rhizome store into a mirror directory, and
   optionally unpacks Zip and Tar payloads into a separate directory.

 * [`serval_maps_push.sh`][] is a Shell script designed to be invoked by
   [`rhizome_mirrord`][] whenever in unpacks a Zip or Tar bundle.  It copies the
   newly unpacked contents to the [Serval Maps testing server][] using
   [rsync(1)][], then prods the testing server to process them by making an
   HTTP request to a particular URL using [curl(1)][].

These two scripts were created to inject Rhizome traffic from New Zealand Red
Cross's KiwiEx 2013 field trial exercise into the Serval Maps visualisation
server, as a demonstration of how Rhizome can be used to transmit situational
awareness field reports back to base.

In deployment, the [`serval_maps_push.sh`][] script was edited to use the
KiwiEx2013 rsync destination directory and URL by changing the `TARGET`
variable from `testing` to `kiwiex-2013`.

The [`rhizome_mirrord`][] script has been designed in a general fashion, and is
suitable for use in other deployments that require a similar mirror directory
of Rhizome content.


[Serval Project]: http://www.servalproject.org/
[`rhizome_mirrord`]: ./rhizome_mirrord
[`serval_maps_push.sh`]: ./serval_maps_push.sh
[Serval Maps testing server]: http://maps.servalproject.org/testing/
[rsync(1)]: http://rsync.samba.org/ftp/rsync/rsync.html
[curl(1)]: http://curl.haxx.se/docs/manpage.html
