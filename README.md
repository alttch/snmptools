# snmptools

Unsafe Rust functions, based directly on net-snmp library for those, which are
not Rust-native yet.

Methods:

* Converts SNMP OIDs to MIB names and vice-versa

Required crate features:

* **dynamic** load libnetsnmp.so dynamically (more cross-platform)

* **static** compile the binary with libnetsnmp.so dep or compile static lib
  inside (a bit faster)
