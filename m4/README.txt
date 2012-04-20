The Autoconf macros in this directory were copied from the GNU Autoconf Archive
http://www.gnu.org/software/autoconf-archive/

To use them, simply concatenate them all into the aclocal.m4 file in the
project root directory:

    cd batphone/jni/servald
    cat m4/* >aclocal.m4

Then you can run autoconf with no special arguments:

    autoconf
    ./configure
    make
