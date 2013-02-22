Serval DNA Utilities
====================
[Serval Project][], February 2013

This directory contains utilities that accompany [Serval DNA][]:

 * [`rhizome_mirrord`][] is a [Python 2.7][] script that continuously extracts
   Rhizome bundles from a local Rhizome store into a mirror directory, and
   optionally unpacks Zip and Tar payloads into a separate directory.

 * [`serval_maps_push.sh`][] is a Shell script designed to be invoked by
   [`rhizome_mirrord`][] whenever in unpacks a Zip or Tar bundle.  It copies the
   newly unpacked contents to the [Serval Maps testing server][] using
   [rsync(1)][], then prods the testing server to process them by making an
   HTTP request to a particular URL using [curl(1)][].

These two scripts were originally created to inject Rhizome traffic from New
Zealand Red Cross's KiwiEx 2013 field trial exercise into the Serval Maps
visualisation server, as a demonstration of how Rhizome can be used to transmit
situational awareness field reports back to base.

The [`rhizome_mirrord`][] script has been designed in a general fashion, and is
suitable for use in other deployments that require a similar mirror of Rhizome
content.

Instructions for use
--------------------

 1. The Rhizome mirror script must be executed on a server that is running as a
    [Serval DNA][] node that receives Rhizome bundles for visualisation in
    Serval Maps.  This server must be running a modern installation of Linux
    and must have continuous Internet access in order to communicate directly
    with the [Serval Maps testing server][].

 2. Ensure that [Git][], [Python 2.7][], [rsync][] and [curl][] are installed
    on the server.

 3. Download a copy of the [Serval DNA][] source code onto the server, for
    example by fetching a read-only clone of the Git repository from GitHub
    and checking out the *development* branch:

        git clone git://github.com/servalproject/serval-dna.git
        cd serval-dna
        git checkout development

 4. Build the [Serval DNA][] `servald` executable by following the [Serval DNA
    build instructions][].

 6. Create a directory to use as the Serval DNA instance directory:

        mkdir /var/local/serval-node
        export SERVALINSTANCE_PATH=/var/local/serval-node

 7. [Configure Serval DNA][] to use the proper network interfaces, to log
    to a suitable log file, etc.

 8. Create directories to hold the Rhizome mirror and the unpacked Zip
    files:

        mkdir /var/local/rhizome-mirror
        mkdir /var/local/rhizome-unpacked

 9. Edit the [`serval_maps_push.sh`][] script to use the suitable Serval Maps
    visualisation page, by changing its `TARGET` variable from `testing` to,
    for example, `kiwiex-2013`.

 9. Start the [Serval DNA][] daemon process:

        ./servald start

10. Start the Rhizome mirror daemon to update the mirror every minute:

        ./utilities/rhizome_mirrord \
            --interval 60 \
            --servald ./servald \
            --instance /var/local/serval-node \
            --mirror-dir /var/local/rhizome-mirror \
            --unpack-dir /var/local/rhizome-unpacked \
            --filter-name 'nz_redcross_*.xml.instance.sam.serval' \
            --exec-on-unpack ./utilities/serval_maps_push.sh \
            --log-to-stdout

    This command will only extract bundles with names matching the
    `--filter-name` glob pattern, so adjust that pattern to match the names of
    the files produced by the application being visualised.

    The `--log-to-stdout` option produces a log of activity on standard output,
    which may be redirected to a file if desired.

    The daemon reports errors on standard output and continues execution, so
    standard output may also be redirected to a file if desired, possibly the
    same as standard error.

    The daemon is relatively untested, and may terminate if there is a code
    error.  It must be watched and restarted if necessary.


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: https://github.com/servalproject/serval-dna
[`rhizome_mirrord`]: ./rhizome_mirrord
[`serval_maps_push.sh`]: ./serval_maps_push.sh
[Serval Maps testing server]: http://maps.servalproject.org/testing/
[Serval DNA build instructions]: ../INSTALL.md
[Configure Serval DNA]: ../doc/Servald-Configuration.md
[Git]:http://git-scm.com/
[Python 2.7]: http://www.python.org/download/releases/2.7/
[rsync]: http://rsync.samba.org/
[rsync(1)]: http://rsync.samba.org/ftp/rsync/rsync.html
[curl]: http://curl.haxx.se/
[curl(1)]: http://curl.haxx.se/docs/manpage.html
