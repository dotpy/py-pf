Nov 22, 2012 -- version 0.0.7
-----------------------------
- Updated to OpenBSD 5.0; the C structures have undergone some minor changes.
- Added support for divert-* options in PF rules.
- Added a new PacketFilter.get_ifaces() method to retrieve the list of
  interfaces and interface drivers known to pf(4).
- Created a new PFIface class representing a network interface and returned
  by the PacketFilter.get_ifaces() method; this class also allows the retrieval
  of per-interface statistics.
- Renamed the PacketFilter.set_ifflag() method to PacketFilter.set_ifflags()
  for consistency with PacketFilter.get_ifflags().


Jul 9, 2011 -- version 0.0.6
-----------------------------
- Added support for packet queueing with ALTQ; three new classes have been
  created (PFAltqCBQ, PFAltqHFSC and PFAltqPriQ), corresponding to the
  schedulers supported by OpenBSD.


Jan 19, 2011 -- version 0.0.5
-----------------------------
- Updated to OpenBSD 4.8; the PF stack has undergone some major changes, such
  as removing the different rule types (nat, rdr, binat ... rules do not exist
  anymore) and introducing 'match' rules.
  This has greatly simplified the PFRuleset class and the PacketFilter methods
  that load/retrieve rules.
- Various bugs have been corrected
- All the code has been reviewed and is now Py3k-ready.


Jul 26, 2009 -- version 0.0.4
-----------------------------
- Updated to OpenBSD-current; modifications include the removal of 'scrub'
  rules and making some ioctl() transactional (set loginterface, set hostid,
  set reassemble and set debug).
- Added addresses to PFTable objects; this should make managing tables much
  more user-friendly.
- Added the PF_RULESET_TABLE ruleset to PFRuleset; this allows loading tables
  along with the other rules and doesn't require that the 'persist' flag be
  set if the table is not yet referenced by any rule.
- Added the PacketFilter.set_reassembly() method.
- Added support for table statistics, by adding the PFTStats object and the
  PacketFilter.get_tstats() and PacketFilter.clear_tstats() methods.


Mar 22, 2009 -- version 0.0.3
-----------------------------
- Added the PFAddr and PFPort classes, representing addresses and ports
  respectively. The PFRuleAddr class is now a simple container for a
  PFAddr/PFPort pair.
- Added table support trough the PFTable and PFTableAddr classes; the
  apropriate methods for managing tables have been added to the PacketFilter
  class.
- The PFPoolAddr class has been removed: now addresses in PFPools are PFAddr
  instances.
- Re-written the PFState class and created the PFStateKey class in accordance
  with the changes to PF's state handling.
- Added the PFUid and PFGid classes, representing user and group IDs.


Jul 06, 2008 -- version 0.0.2
-----------------------------
- Added support for loading rulesets, by means of the
  PacketFilter.load_ruleset() method
- Added the possibility to selectively kill states, based on address family,
  transport layer protocol, source and destination addresses and interface
  name, thanks to the PacketFilter.kill_states() method
- Added the PacketFilter.set_hostid() method, which allows you to set the
  hostid, a numeric value used by pfsync(4) to identify which host created
  state table entries


Apr 26, 2008 -- version 0.0.1
-----------------------------
- Initial release
