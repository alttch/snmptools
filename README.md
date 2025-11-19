# snmptools

Unsafe Rust functions, based directly on net-snmp library for those, which are
not Rust-native yet.

Methods:

- Converts SNMP OIDs to MIB names and vice-versa

Required crate features:

- **static** (default) - compiles the binary with libnetsnmp.so dep or compile
  static lib inside (a bit faster)

- **dynamic** - loads libnetsnmp.so or libnetsnmp.dylib dynamically (more cross-platform, not support windows system)

## Example

Prepare the system

```shell
# Linux
apt-get install libsnmp-dev snmp-mibs-downloader
# MacOS
brew install net-snmp
```

```rust
use snmptools::{Oid};

snmptools::init(&snmptools::Config::new().mibs(&["./ibmConvergedPowerSystems.mib"])).unwrap();
let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
let name = snmptools::get_name(&snmp_oid).unwrap();
assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
let snmp_oid2 = snmptools::get_oid(&name).unwrap();
assert_eq!(snmp_oid, snmp_oid2);
```
