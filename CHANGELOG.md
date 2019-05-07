May 7, 2019 -- version 0.2.1
----------------------------
- Tested on OpenBSD 6.5


Nov 23, 2018 -- version 0.2.0
-----------------------------
- Updated to OpenBSD 6.4


Jun 13, 2018 -- version 0.1.9
-----------------------------
- Updated to OpenBSD 6.3 (many thanks to
  [Jasper Lievisse Adriaanse](https://github.com/jasperla) for his contribution)
- Support for syncookies was added to the `PacketFilter` class through 3 new
  methods:
  - `PacketFilter.get_synflood_watermarks()`
  - `PacketFilter.set_synflood_watermarks()`
  - `PacketFilter.set_syncookies()`
- Added a new `PFThreshold` class for `max-pkt-rate` thresholds
- Added a new `PFDivert` class to represent divert sockets


Jan 15, 2018 -- version 0.1.8
-----------------------------
- Updated to OpenBSD 6.2 (many thanks to
  [Nathan Wheeler](https://github.com/nahun) for his contribution)
- Some little changes were made to the queueing part to integrate flows:
  - a new `FlowQueue` object was created
  - `PFQueue` objects have a new `flowqueue` attribute
- HFSC_* constants have been replaced with PFQS_* constants
- `PFStatus.since` now contains the number of seconds after machine uptime that
  Packet Filter was last started or stopped (not anymore since the epoch).


Sep 16, 2016 -- version 0.1.7
-----------------------------
- Updated to OpenBSD 6.0


May 1, 2016 -- version 0.1.6
-----------------------------
- Updated to OpenBSD 5.9


Oct 25, 2015 -- version 0.1.5
-----------------------------
- Updated to OpenBSD 5.8


May 5, 2015 -- version 0.1.4
----------------------------
- Updated to OpenBSD 5.7
- Removed `pf._struct.BufferStructure` that was originally meant to overcome
  the 1024 bytes limit in `fcntl.ioctl()` and is no longer needed.


Nov 6, 2014 -- version 0.1.3
----------------------------
- Updated to OpenBSD 5.6
- Removed the last traces of ALTQ
- Fixed a little bug in `PFState._to_string()`


May 27, 2014 -- version 0.1.2
-----------------------------
- Updated to OpenBSD 5.5
- OpenBSD 5.5 has a new queueing system; thus all the queue classes
  (`PFAltqCBQ`, `PFAltqHFSC` and `PFAltqPriQ`) and the corresponding stats
  classes (`CBQStats`, `HFSCStats` and `PriQStats`) have been replaced by the
  `PFQueue` and `PFQueueStats` classes respectively.
- Methods for retrieving and adding queues in the `PacketFilter` class (i.e.
  `get_altqs()` and `add_altqs()`) have been replaced (by `get_queues()` and
  `load_queues()` respectively). Queues are now cleared along with rules, so
  the `clear_altqs()` method has been removed.


Nov 10, 2013 -- version 0.1.1
-----------------------------
- Updated to OpenBSD 5.4


May 2, 2013 -- version 0.1.0
----------------------------
- Updated to OpenBSD 5.3


Oct 21, 2012 -- version 0.0.9
-----------------------------
- Updated to OpenBSD 5.2
- Printing a `PFIface` object now returns a string similar to the output of the
  command `pfctl -sI -vv`
- Fixed a bug in `PFRule` that prevented `rdr-to` rules from being correctly
  converted to strings
- Fixed a couple of bugs in the string representation of `PFState` objects
- Added filtering capabilities to `PacketFilter.get_ruleset()`: now it's
  possible to retrieve only rules with specific attribute values (e.g.
  `filter.get_ruleset(ifname="em0")`)
- Added the `set_optimization()` and `get_optimization()` methods to
  `PacketFilter` (thanks Colin!)
- Fixed a bug in `PFAddr._from_str()` which didn't allow interface groups as
  addresses (thanks Colin!)
- Added the `pf.lib` module containing some higher-level classes that make
  loading PF rules much easier


Jun 28, 2012 -- version 0.0.8
-----------------------------
- Updated to OpenBSD 5.1
- Module renamed to pf for better compliance with PEP8
- Fixed a ZeroDivisionError in PFStatus._to_string() when runtime == 0
- Added support for ALTQ statistics; three new classes have been created
  (CBQStats, HFSCStats and PriQStats), corresponding to the schedulers
  supported by OpenBSD.
- Fixed a few calls to ctonm() in PFRule.py that didn't pass the af argument
- Added probability and options to the string representation of PFRule
  objects
- Fixed a regexp error in PFRule.py that prevented the correct parsing of
  some port operands
- Fixed bug in PFUtils.rate2str which prevented correct handling of floating
  point numbers
- Test suite completely re-written and run with `python setup.py test`


Nov 22, 2012 -- version 0.0.7
-----------------------------
- Updated to OpenBSD 5.0; the C structures have undergone some minor changes.
- Added support for `divert-*` options in PF rules.
- Added a new `PacketFilter.get_ifaces()` method to retrieve the list of
  interfaces and interface drivers known to pf(4).
- Created a new `PFIface` class representing a network interface and returned
  by the `PacketFilter.get_ifaces()` method; this class also allows the
  retrieval of per-interface statistics.
- Renamed the `PacketFilter.set_ifflag()` method to `PacketFilter.set_ifflags()`
  for consistency with `PacketFilter.get_ifflags()`.


Jul 9, 2011 -- version 0.0.6
-----------------------------
- Added support for packet queueing with ALTQ; three new classes have been
  created (`PFAltqCBQ`, `PFAltqHFSC` and `PFAltqPriQ`), corresponding to the
  schedulers supported by OpenBSD.


Jan 19, 2011 -- version 0.0.5
-----------------------------
- Updated to OpenBSD 4.8; the PF stack has undergone some major changes, such
  as removing the different rule types (nat, rdr, binat ... rules do not exist
  anymore) and introducing 'match' rules.
  This has greatly simplified the `PFRuleset` class and the `PacketFilter`
  methods that load/retrieve rules.
- Various bugs have been corrected
- All the code has been reviewed and is now Py3k-ready.


Jul 26, 2009 -- version 0.0.4
-----------------------------
- Updated to OpenBSD-current; modifications include the removal of 'scrub'
  rules and making some ioctl() transactional (set loginterface, set hostid,
  set reassemble and set debug).
- Added addresses to `PFTable` objects; this should make managing tables much
  more user-friendly.
- Added the `PF_RULESET_TABLE` ruleset to `PFRuleset`; this allows loading
  tables along with the other rules and doesn't require that the 'persist' flag
  be set if the table is not yet referenced by any rule.
- Added the `PacketFilter.set_reassembly()` method.
- Added support for table statistics, by adding the `PFTStats` object and the
  `PacketFilter.get_tstats()` and `PacketFilter.clear_tstats()` methods.


Mar 22, 2009 -- version 0.0.3
-----------------------------
- Added the `PFAddr` and `PFPort` classes, representing addresses and ports
  respectively. The `PFRuleAddr` class is now a simple container for a
  `PFAddr`/`PFPort` pair.
- Added table support trough the `PFTable` and `PFTableAddr` classes; the
  apropriate methods for managing tables have been added to the `PacketFilter`
  class.
- The `PFPoolAddr` class has been removed: now addresses in `PFPools` are
  `PFAddr` instances.
- Re-written the `PFState` class and created the `PFStateKey` class in
  accordance with the changes to PF's state handling.
- Added the `PFUid` and `PFGid` classes, representing user and group IDs.


Jul 06, 2008 -- version 0.0.2
-----------------------------
- Added support for loading rulesets, by means of the
  `PacketFilter.load_ruleset()` method
- Added the possibility to selectively kill states, based on address family,
  transport layer protocol, source and destination addresses and interface
  name, thanks to the `PacketFilter.kill_states()` method
- Added the `PacketFilter.set_hostid()` method, which allows you to set the
  hostid, a numeric value used by pfsync(4) to identify which host created
  state table entries


Apr 26, 2008 -- version 0.0.1
-----------------------------
- Initial release
