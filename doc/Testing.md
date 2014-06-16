Serval DNA Testing
==================
[Serval Project][], June 2014

[Serval DNA][] is tested using a suite of [test scripts](../tests/) written in
the [Bash][] shell scripting language, using the Serval Project's own [Bash
Test Framework][].  These scripts are [integration tests][] focussed on the
Serval DNA component and its external interfaces.

Test Framework
--------------

The [Bash Test Framework][] performs common testing work, so that test
developers can focus on the specifics of their test cases and test cases
contain a minumum of [boilerplate code][]:

 * creates a temporary working directory to isolate each test case
 * invokes each test case's set-up, test, finalise, and tear-down functions in
   a defined order, guaranteeing to always call the latter two
 * provides a rich set of assertion functions
 * records the outcome of each test case: PASS, FAIL or ERROR
 * records a detailed log of the execution of each test case
 * removes temporary working directories and files after each test case
 * kills any stray processes after each test case
 * runs test cases in parallel if so directed
 * reports progress during execution

Some features that may be added in future are:

 * conformance with [Test Anything Protocol][TAP]
 * support for a SKIP test outcome
 * formal versioning of the Test Framework and parts of its API, to catch
   incompatibilities between test scripts and Framework upgrades

Prerequisites
-------------

The [Bash Test Framework][] requires the following execution environment:

 * [Bash][] version 3.2.48 or later
 * [GNU grep][] version 2.7 or later
 * [GNU sed][] version 4.2 or later
 * [GNU awk][] version 3.1 or later
 * [pgrep][] and [pkill][] version 593 or later (Solaris) or from procps-ng 3.3
   or later (Linux)

Before running any tests, all the executables and other artifacts under test
(ie, the **servald** executable), plus all test utilities, must be
[built](../INSTALL.md).

Test scripts
------------

Executing a test script without any arguments causes it to run all the test
cases that it defines, one at a time.  The script will terminate once all test
cases have been run, and its exit status will be zero only if all test cases
reported PASS.

Every test script uses the [Bash Test Framework][] to parse its command line,
so the following options are supported by all test scripts:

 * __`-l`__ or __`--list`__ causes the script to print a list of all its test
   cases on standard output, instead of executing them

 * __`-t`__ or __`--trace`__ sets the Bash `-x` option during execution of each
   test case, which adds much more detail to the test logs

 * __`-v`__ or __`--verbose`__ causes test logs to be sent to standard output
   during execution of the tests, so the developer can watch a test as it runs
   (this version is incompatible with running tests in parallel)

 * __`-E`__ or __`--stop-on-error`__ causes the test script to stop running new
   test cases as soon as any test reports ERROR, and to wait for currently
   running test cases to finish

 * __`-F`__ or __`--stop-on-failure`__ causes the test script to stop running
   new test cases as soon as any test reports FAIL, and to wait for currently
   running test cases to finish

 * __`-j N`__ or __`--jobs=N`__ causes up to __N__ test cases to be run
   concurrently, which can greatly speed the rate of completion of a large test
   run, since most tests spend much of their time either sleeping or i/o bound

 * __`-f PREFIX`__ or __`--filter=PREFIX`__ causes only those test cases whose
   names begin with __PREFIX__ to be executed

 * __`-f N`__ or __`--filter=N`__ causes only test case number __N__ to be
   executed (test cases are numbered in the order they are defined in the
   script)

 * __`-f M-N`__ or __`--filter=M-N`__ causes only test cases numbers __M__
   through to __N__ (inclusive) to be executed (test cases are numbered in the
   order they are defined in the script); if __M__ is omitted then all cases up
   to number __N__ are executed; if __N__ is omitted then all test cases from
   number __M__ and above are executed

 * __`-f M,N,...`__ or __`--filter=M,N,...`__ causes only test cases __M__ and
   __N__ (... etc.) to be executed (test cases are numbered in the order they
   are defined in the script)

There are other options as well.  To see a complete and up-to-date summary, use
the __`--help`__ option:

    $ ./tests/all --help

Aggregate scripts
-----------------

Some test scripts simply aggregate other scripts, providing a convenient way to
execute many tests with a single command.  Aggregate scripts behave in all
respects like a normal test script: the command line options and exit status
are the same.

The most notable aggregate script is [tests/all](../tests/all), which runs all
available tests except long-running, resource-hungry “stress” tests:

    $ ./tests/all
    1 [PASS.] (logging) By default, only errors and warnings are logged to stderr
    2 [PASS.] (logging) Configure all messages logged to stderr
    3 [PASS.] (logging) Configure no messages logged to stderr
    4 [PASS.] (logging) By Default, all messages are appended to a configured file
    ...
    158 [PASS.] (rhizomeprotocol) One way direct pull bundle from configured peer
    159 [PASS.] (rhizomeprotocol) Two-way direct sync bundles with configured peer
    160 [PASS.] (directory_service) Publish and retrieve a directory entry
    161 [PASS.] (directory_service) Ping via relay node
    161 tests, 161 pass, 0 fail, 0 error
    $

Test logs
---------

All test scripts write their test logs into the `testlog` sub-directory
(relative to the current working directory), which has the following structure:

    ./testlog/
        SCRIPTNAME/
            1.FirstTestCaseName.RESULT/
                log.txt
                ... other files...
            2.SecondTestCaseName.RESULT/
                log.txt
                ... other files...
        SECONDSCRIPTNAME/
            1.first_test_case_name.RESULT/
                log.txt
                ... other files...
            2.second_test_case_name.RESULT/
                log.txt
                ... other files...
        ... more script directories...

where `SCRIPTNAME` and `SECONDSCRIPTNAME` are the names of the test scripts,
`FirstTestCaseName`, `first_test_case_name`, etc. are the names of the tests
within those scripts, and `RESULT` is either `ERROR`, `FAIL` or `PASS`.  An
aggregate test script writes logfiles for all the test cases it includes under
its own SCRIPTNAME, not under the names of the scripts it includes.

Whenever a test script starts, it deletes its `testlog/SCRIPTNAME` directory
and all its contents, so the logs from previous runs are lost.

Every test case produces a `log.txt` file, and may also produce other files to
assist diagnosis in case of failure or to supplement a pass result, eg,
performance statistics, code coverage data, network packet logs for
reproducibility.

Source code coverage
--------------------

The [Bash Test Framework][] has command-line options to support per-test-case
[source code test coverage][] analysis using [GCC][] and [gcov(1)][].  An
aggregate coverage analysis can easily be generated with no special options to
test scripts.

To generate code coverage information for [Serval DNA][], modify the standard
[build](../INSTALL.md) procedure by adding CFLAGS and LDFLAGS arguments to the
`./configure` step:

    ...
    $ ./configure CFLAGS='-g -O0 --coverage' LDFLAGS='--coverage'
    $ make
    ...

This will generate one [GCNO][] file for every object file, in the same
directory as the object file.

Once **servald** has been built using these flags, invoking it will generate
some [GCDA][] coverage data files, one per source file, in the same directory
as the [GCNO][] files.  Repeated invocations will accumulate coverage data in
the same files.  The environment variables `GCOV_PREFIX` and
`GCOV_PREFIX_STRIP` can be used to change the directory where the [GCDA][] data
files are written.

### Aggregate code coverage

To generate aggregate code coverage for a test run:

    $ make covzero
    $ ./tests/all
    ...
    $ make covhtml
    $ www-browser ./coverage_html/index.html
    ...

The coverage report will reflect exactly the accumulated coverage of all tests
run between `make covzero` and `make covhtml`.  The above example runs all
tests (except stress tests) but any combination may be run, including manual
invocations of **servald**.  The **servald** executable must be invoked at
least once after `make covzero`, or `make covhtml` will fail with an error, for
lack of coverage data.

If more tests are run without invoking `make covzero`, then the coverage data
will sum with the existing coverage data since the last `make covzero`.

### Per-test-case code coverage

**Note**: Per-test-case coverage support is of very limited use because of
deficiencies in the coverage data processing utilities (see below).

If the __`--coverage`__ option is given to a test script, then it sets the
`GCOV_PREFIX` and `GCOV_PREFIX_STRIP` environment variables while running each
test case, causing each case's generated [GCDA][] coverage data files to be
created under the case's own log directory:

    ./testlog/
        SCRIPTNAME/
            N.TestCaseName.RESULT/
                log.txt
                gcov/
                    home/username/src/serval-dna/objs_servald/cli.gcda
                    home/username/src/serval-dna/objs_servald/commandline.gcda
                    ...
                    home/username/src/serval-dna/objs_servald/nacl/src/crypto_auth_hmacsha256_ref/hmac.c
                    ...

In theory, these per-test-case [GCDA][] data files could be merged to produce
coverage data for any desired combination of test cases, but there is currently
no command-line utility available to perform this merge.  The code for merging
undoubtably exists in the *libgcov* [atexit(3)][] callback, which sums the
process's accumulated execution counts into any existing [GCDA][] files, but no
work has been done to extract this code into a utility.

If the __`--geninfo`__ option is given (which implies `--coverage`), the test
framework will invoke [geninfo][] after each test case completes, to generate
one [lcov][] *tracefile* per case named `coverage.info` located in the case's
own log directory:

    ./testlog/
        SCRIPTNAME/
            N.TestCaseName.RESULT/
                log.txt
                coverage.info

**Note**: The `--geninfo` option must be accompanied by at least one
__`--gcno-dir=PATH`__ option, or the `TFW_GCNO_PATH` environment variable must
be set to a list of colon-separated directory paths.  The test framework
recursively searches all these directories looking for [GCNO][] files, which it
then supplies to [geninfo][], which uses them to find the source files and
[GCDA][] files produced by `--coverage`.

The per-test-case tracefiles produced by [geninfo][] may be merged together
using the `lcov --add-tracefile` option, and may also be combined into a single
coverage report by passing many tracefile arguments to the [genhtml][] utility.
Unfortunately, both of these operations are prohibitively slow, which makes the
`--geninfo` option of limited use for the time being.

-----
**Copyright 2013 Serval Project Inc.**
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ./LICENSE-DOCUMENTATION.md
[Serval DNA]: ../README.md
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[Bash Test Framework]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:bash_test_framework
[GNU grep]: http://www.gnu.org/software/grep/
[GNU sed]: http://www.gnu.org/software/sed/
[GNU awk]: http://www.gnu.org/software/gawk/
[pgrep]: http://en.wikipedia.org/wiki/Pgrep
[pkill]: http://en.wikipedia.org/wiki/Pkill
[integration tests]: http://en.wikipedia.org/wiki/Integration_testing
[boilerplate code]: http://en.wikipedia.org/wiki/Boilerplate_code
[TAP]: http://en.wikipedia.org/wiki/Test_Anything_Protocol
[source code test coverage]: http://en.wikipedia.org/wiki/Code_coverage
[GCC]: https://gcc.gnu.org/
[gcov(1)]: https://gcc.gnu.org/onlinedocs/gcc/Gcov.html
[GCNO]: https://gcc.gnu.org/onlinedocs/gcc-3.4.2/gcc/Gcov-Data-Files.html
[GCDA]: https://gcc.gnu.org/onlinedocs/gcc-3.4.2/gcc/Gcov-Data-Files.html
[lcov]: http://ltp.sourceforge.net/archive/old_pages/coverage/lcov.php
[geninfo]: http://ltp.sourceforge.net/coverage/lcov/geninfo.1.php
[genhtml]: http://ltp.sourceforge.net/coverage/lcov/genhtml.1.php
[atexit(3)]: http://man7.org/linux/man-pages/man3/atexit.3.html
