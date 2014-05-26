Serval DNA Mesh Packet Filtering
================================
[Serval Project][], May 2014

The [Serval DNA][] daemon can perform filtering on all incoming and outgoing
[MDP][] packets, ie, packets that are addressed to the local node and packets
that originate from the local node.

[Serval DNA][] cannot filter packets that it is forwarding to other nodes.

The original MDP packet filtering capability was funded by a [grant][] from the
[New America Foundation][NAF]'s [Open Technology Institute][OTI].

How to configure packet filtering
---------------------------------

Packet filtering is disabled by default, so all packets are allowed.

To enable MDP packet filtering, set the `mdp.filter_rules_path` [config
option][] to the absolute or relative path of a _filter rules_ file.  Relative
paths are interpreted with respect to the same directory that contains the
configuration file.

### Example 1

    allow <>*:1-7
    allow *:1-10 <>*
    allow broadcast:70 <DEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD
    allow >ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB:20100
    drop <*:8
    allow <>0123012301230123012301230123012301230123012301230123012301230123
    allow <>4567456745674567456745674567456745674567456745674567456745674567:12-18
    drop all

### Grammar

    rules := optspace [ rule optspace ( sep optspace rule optspace ){0..} ]
    sep := "\n" | ";"
    rule := verb space which
    verb := "allow" | "drop"
    which := "all" | pattern
    pattern := [ endpoint optspace ] direction optspace endpoint
    direction := ">" | "<" | "<>"
    endpoint := sidany [ optspace ":" optspace portrange ]
    sidany := "*" | sidhex | "broadcast"
    sidhex := hexdigit {64}
    portrange := port optspace [ "-" optspace port ]
    port := hexport | decport
    hexport := "0x" hexdigit {1..8}
    decport := decdigit {1..10}
    decdigit := "0".."9"
    hexdigit := decdigit | "A".."F" | "a".."f"
    optspace := " " {0..}
    space := " " {1..}

### How rules work

For each incoming and outgoing packet, all packet rules are tested in the order
that they appear in the rules file.  The first rule that matches the packet
determines whether the packet is *allowed* or *dropped*, and no more rules are
tested.  If no rules match, the packet is *allowed* by default.

 * Rules are separated by a single newline (ASCII 10) or semicolon `;`.

 * Each rule is an *action* (`drop` or `allow`) followed either by the word
   `all` or followed by an optional *local pattern* followed by a *direction*
   and a *remote pattern*.

 * A rule with the `all` word matches all packets, which means that any
   following rules are ignored.  So an *all rule* should be the last rule in
   the file.

 * A non-all rule only matches a packet if its local pattern, direction, *AND*
   remote pattern all match.

 * The local pattern, if given, is tested against the packet's *local address*;
   if absent, all local addresses match.  For incoming packets this means the
   recipient (destination) address, and for outgoing packets this means the
   sending (originating) address.

 * The direction is one of `<`, `>` or `<>`, which causes the rule to match
   only incoming packets, only outgoing packets, or both.

 * The remote pattern is tested against the packet's *remote address*.  For
   incoming packets this means the sending (originating) address, and for
   outgoing packets this means the recipient (destination) address.

 * A pattern (local or remote) is a SID optionally followed by a colon `:` and
   a range of [MDP port][] numbers.

 * A pattern only matches an address if its SID matches the address's [SID][]
   *AND* its port number lies within the address's port number range.  If the
   pattern has no port number range, then it matches all port numbers.

 * A pattern's SID can be given either as 64 hexadecimal digits, which matches
   that [SID][] exactly, or the word `broadcast`, which matches only the
   all-bits-set [SID][] (`FFFF....FF`), or the star symbol `*` which matches
   any [SID][].

 * A port number range is either a single port number, which matches only that
   port number exactly, or a pair of port numbers separated by a dash `-` where
   the second number is greater than the first.  Each port number is either a
   decimal integer in the range 1 to 4294967295 inclusive or a hexadecimal
   number prefixed with `0x` in the range `0x1` to `0xffffffff`.

### Interpretation of example 1

The rules file shown in Example 1 above has the following meaning:

  * `allow <>*:1-7`

    allows all incoming packets originating from remote ports 1 through 7, and
    allows all outgoing packets (which will probably be replies) to the same
    range of remote ports

  * `allow *:1-10 <>*`

    allows all incoming packets to local ports between 1 and 10 inclusive, and
    all outgoing packets from those ports

  * `allow broadcast:70 <DEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD`

    allows all broadcast packets sent to local port 70 from any port on the node
    with SID `DEAD...DEAD`

  * `allow >ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB:20100`

    allows all outgoing packets to port 20100 on the node with SID `ABAB...ABAB`

  * `drop <*:8`

    drops all incoming packets (that were not allowed by prior rules) sent from
    port 8 on any remote node

  * `allow <>0123012301230123012301230123012301230123012301230123012301230123`

    allows all incoming and outgoing packets (that were not dropped by prior
    rules) from and to the node with SID `0123...0123`

  * `allow <>4567456745674567456745674567456745674567456745674567456745674567:12-18`

    allows all incoming and outgoing packets (that were not dropped by prior
    rules) from and to ports 12 through 18 inclusive on the node with SID
    `4567...4567`

  * `drop all`

    drops all incoming and outgoing packets that were not allowed by prior rules

Special case: SID whitelist
---------------------------

A filter rules file that whitelists a set of [SID][]s will have the following
form:

    allow <>0001000100010001000100010001000100010001000100010001000100010001
    allow <>0002000200020002000200020002000200020002000200020002000200020002
    allow <>0003000300030003000300030003000300030003000300030003000300030003
    ...
    allow <>000n000n000n000n000n000n000n000n000n000n000n000n000n000n000n000n
    drop all

where the symbols `0001...0001` through `000n...000n` are replaced by the
hexadecimal representations of the actual SIDs in the whitelist.

**Note**: If the final line `drop all` is missing, then the whitelist will have
no effect.

Special case: SID blacklist
---------------------------

A filter rules file that blacklists a set of [SID][]s will have the following
form:

    drop <>0001000100010001000100010001000100010001000100010001000100010001
    drop <>0002000200020002000200020002000200020002000200020002000200020002
    drop <>0003000300030003000300030003000300030003000300030003000300030003
    ...
    drop <>000n000n000n000n000n000n000n000n000n000n000n000n000n000n000n000n

where the symbols `0001...0001` through `000n...000n` are replaced by the
hexadecimal representations of the actual SIDs in the blacklist.


-----
**Copyright 2014 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[Serval DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:
[config option]: ./Servald-Configuration.md
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[MDP]: ./Mesh-Datagram-Protocol.md
[MDP port]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_number
