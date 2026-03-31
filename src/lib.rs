#![ doc = include_str!( concat!( env!( "CARGO_MANIFEST_DIR" ), "/", "README.md" ) ) ]
#[cfg(not(feature = "dynamic"))]
extern crate netsnmp_sys_nocrypto;

pub use asn1_rs::Oid;
#[cfg(not(feature = "dynamic"))]
use netsnmp_sys_nocrypto as netsnmp_sys;
#[cfg(feature = "dynamic")]
use once_cell::sync::OnceCell;
use std::env;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;

#[cfg(feature = "dynamic")]
static NETSNMP: OnceCell<libloading::Library> = OnceCell::new();

#[cfg(feature = "dynamic")]
const MAX_OID_LEN: usize = 128;
#[cfg(not(feature = "dynamic"))]
const MAX_OID_LEN: usize = netsnmp_sys::MAX_OID_LEN;

#[cfg(feature = "dynamic")]
type OidElem = u64;
#[cfg(not(feature = "dynamic"))]
type OidElem = netsnmp_sys::oid;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ErrorKind {
    Failed,
    InvalidData,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl std::error::Error for Error {}

impl Error {
    #[inline]
    pub fn invalid_data(msg: impl fmt::Display) -> Self {
        Self {
            kind: ErrorKind::InvalidData,
            message: msg.to_string(),
        }
    }
    #[inline]
    pub fn failed(msg: impl fmt::Display) -> Self {
        Self {
            kind: ErrorKind::Failed,
            message: msg.to_string(),
        }
    }
    #[inline]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

const MAX_NAME_LEN: usize = 1024;

#[derive(Clone)]
pub struct Config<'a> {
    #[cfg(feature = "dynamic")]
    lib_path: &'a str,
    app_name: &'a str,
    mibs: &'a [&'a str],
    mib_dirs: &'a [&'a str],
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            #[cfg(all(feature = "dynamic", target_os = "linux"))]
            lib_path: "libnetsnmp.so",
            #[cfg(all(feature = "dynamic", target_os = "macos"))]
            lib_path: "libnetsnmp.dylib",
            app_name: env!("CARGO_CRATE_NAME"),
            mibs: <_>::default(),
            mib_dirs: <_>::default(),
        }
    }
}

impl<'a> Config<'a> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
    #[cfg(feature = "dynamic")]
    #[inline]
    pub fn lib_path(mut self, path: &'a str) -> Self {
        self.lib_path = path;
        self
    }
    #[inline]
    pub fn mibs(mut self, mibs: &'a [&'a str]) -> Self {
        self.mibs = mibs;
        self
    }
    #[inline]
    pub fn mib_dirs(mut self, mib_dirs: &'a [&'a str]) -> Self {
        self.mib_dirs = mib_dirs;
        self
    }
    #[inline]
    pub fn app_name(mut self, name: &'a str) -> Self {
        self.app_name = name;
        self
    }
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
///
/// # Panics
///
/// Will panic if app_name contains a zero-char
pub fn init(config: &Config) -> Result<(), Error> {
    if !config.mibs.is_empty() {
        unsafe {
            env::set_var("MIBS", config.mibs.join(":"));
        }
    }
    if !config.mib_dirs.is_empty() {
        unsafe {
            env::set_var("MIBDIRS", config.mib_dirs.join(":"));
        }
    }
    let app_name: CString = CString::new(config.app_name).unwrap();
    #[cfg(feature = "dynamic")]
    unsafe {
        if config.lib_path.is_empty() {
            return Err(Error::failed("lib path not set"));
        }
        let lib = libloading::Library::new(config.lib_path).map_err(Error::failed)?;
        let init: libloading::Symbol<unsafe extern "C" fn(name: *const c_char)> =
            lib.get(b"init_snmp").map_err(Error::failed)?;
        init(app_name.as_ptr());
        NETSNMP.set(lib).unwrap();
    }
    #[cfg(not(feature = "dynamic"))]
    {
        unsafe {
            netsnmp_sys::init_snmp(app_name.as_ptr());
        }
    }
    Ok(())
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
///
/// # Panics
///
/// Will panic if not initialized
pub fn get_name(snmp_oid: &Oid) -> Result<String, Error> {
    let (n_oid, n_len) = oid_to_array_and_len(snmp_oid)?;
    let mut name_buf = [0_i8; MAX_NAME_LEN];
    #[cfg(feature = "dynamic")]
    unsafe {
        let lib = NETSNMP.get().unwrap();
        let snprint_objid: libloading::Symbol<
            unsafe extern "C" fn(
                buf: *mut c_char,
                buf_len: usize,
                objid: *const u64,
                objidlen: usize,
            ),
        > = lib.get(b"snprint_objid").map_err(Error::failed)?;
        snprint_objid(
            name_buf.as_mut_ptr(),
            MAX_NAME_LEN,
            n_oid.as_slice().as_ptr(),
            n_len,
        );
    }
    #[cfg(not(feature = "dynamic"))]
    unsafe {
        netsnmp_sys::snprint_objid(
            name_buf.as_mut_ptr().cast::<c_char>(),
            MAX_NAME_LEN,
            n_oid.as_slice().as_ptr(),
            n_len,
        );
    }
    let name = unsafe { CStr::from_ptr(name_buf.as_mut_ptr().cast_const().cast::<c_char>()) };
    Ok(name.to_string_lossy().to_string())
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
///
/// # Panics
///
/// Will panic if not initialized
pub fn get_oid(name: &'_ str) -> Result<Oid<'_>, Error> {
    let mut n_oid: [OidElem; MAX_OID_LEN] = [0; MAX_OID_LEN];

    let c_name = CString::new(name).map_err(Error::invalid_data)?;
    let mut len = MAX_OID_LEN;
    #[cfg(feature = "dynamic")]
    let res = unsafe {
        let lib = NETSNMP.get().unwrap();
        let get_node: libloading::Symbol<
            unsafe extern "C" fn(name: *const c_char, oid: *mut u64, oid_len: *mut usize) -> i32,
        > = lib.get(b"get_node").map_err(Error::failed)?;
        get_node(c_name.as_ptr(), n_oid.as_mut_ptr(), &mut len)
    };
    #[cfg(not(feature = "dynamic"))]
    let res = unsafe { netsnmp_sys::get_node(c_name.as_ptr(), n_oid.as_mut_ptr(), &mut len) };
    if res == 0 {
        Err(Error::failed("Unable to get SNMP OID"))
    } else {
        #[allow(clippy::unnecessary_cast)]
        Oid::from(&n_oid[..len].iter().map(|v| *v as u64).collect::<Vec<u64>>())
            .map_err(|_| Error::failed("Unable to create SNMP OID"))
    }
}

#[cfg(not(feature = "dynamic"))]
pub fn get_type(snmp_oid: &Oid) -> Result<u8, Error> {
    let (n_oid, n_len) = oid_to_array_and_len(snmp_oid)?;
    unsafe {
        let tree_head = netsnmp_sys::get_tree_head();
        if tree_head.is_null() {
            return Err(Error::failed("MIB tree not initialized"));
        }

        let node = netsnmp_sys::get_tree(n_oid.as_ptr(), n_len, tree_head);
        if node.is_null() {
            return Err(Error::failed("OID not found in MIB tree"));
        }
        Ok(netsnmp_sys::mib_to_asn_type((*node)._type.into()))
    }
}

// with dynamic lib, we don't know the struct Tree, and can't get _type field
// here is an attempt:
// #[cfg(feature = "dynamic")]
// pub fn get_type(snmp_oid: &Oid) -> Result<u8, Error> {
//     use std::ffi::c_void;
//
//     let (n_oid, n_len) = oid_to_array_and_len(snmp_oid)?;
//
//     let lib = NETSNMP.get().unwrap();
//
//     let get_tree_head: libloading::Symbol<unsafe extern "C" fn() -> *mut c_void> =
//         unsafe { lib.get(b"get_tree_head").map_err(Error::failed)? };
//     let get_tree: libloading::Symbol<
//         unsafe extern "C" fn(oid: *const u64, oid_len: usize, tree: *mut c_void) -> *mut c_void,
//     > = unsafe { lib.get(b"get_tree").map_err(Error::failed)? };
//     let _mib_to_asn_type: libloading::Symbol<unsafe extern "C" fn(i32) -> u8> =
//         unsafe { lib.get(b"mib_to_asn_type").map_err(Error::failed)? };
//
//     let tree_head = unsafe { get_tree_head() };
//     if tree_head.is_null() {
//         return Err(Error::failed("MIB tree not initialized"));
//     }
//     let node = unsafe { get_tree(n_oid.as_ptr(), n_len, tree_head) };
//     if node.is_null() {
//         return Err(Error::failed("OID not found in MIB tree"));
//     }
// }

fn oid_to_array_and_len(snmp_oid: &Oid) -> Result<([OidElem; MAX_OID_LEN], usize), Error> {
    let mut n_oid: [OidElem; MAX_OID_LEN] = [0; MAX_OID_LEN];

    let mut n_len = 0;
    for (n, val) in snmp_oid
        .iter()
        .ok_or(Error::invalid_data("SNMP OID is empty"))?
        .enumerate()
    {
        if n >= MAX_OID_LEN {
            return Err(Error::invalid_data("SNMP OID too long"));
        }
        n_oid[n] = val;
        n_len += 1;
    }
    Ok((n_oid, n_len))
}

#[cfg(test)]
mod test {
    #[cfg(not(feature = "dynamic"))]
    use super::get_type;
    use super::{Config, MAX_OID_LEN, Oid, get_name, get_oid, init};
    use std::sync::Once;

    #[cfg(not(feature = "dynamic"))]
    use netsnmp_sys_nocrypto as netsnmp_sys;

    #[cfg(not(feature = "dynamic"))]
    const ASN_OCTET_STR: u8 = netsnmp_sys::ASN_OCTET_STR;

    static INIT: Once = Once::new();

    fn init_once() {
        INIT.call_once(|| {
            init(&Config::new().mibs(&["./ibmConvergedPowerSystems.mib"])).unwrap();
        });
    }

    #[test]
    fn test_mib() {
        init_once();
        let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
        let name = get_name(&snmp_oid).unwrap();
        assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
        let snmp_oid2 = get_oid(&name).unwrap();
        assert_eq!(snmp_oid, snmp_oid2);
    }

    #[test]
    fn test_mixed_mib() {
        init_once();
        let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
        let oid = get_oid("IBM-CPS-MIB::ibm.6.201.3").unwrap();
        assert_eq!(oid, snmp_oid);
    }

    #[cfg(not(feature = "dynamic"))]
    #[test]
    fn test_mib_type_ibm() {
        init_once();
        let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();

        let mib_name = get_name(&snmp_oid).unwrap();
        assert_eq!(mib_name, "IBM-CPS-MIB::cpsSystemSendTrap");

        // Verify type lookup
        let t = get_type(&snmp_oid).unwrap();

        // Notifications are ASN_NULL in Net-SNMP
        assert_eq!(t, ASN_OCTET_STR);
    }

    #[test]
    fn test_mib_type_oid_too_long() {
        init_once();
        let snmp_oid = Oid::from(&[0; MAX_OID_LEN + 1]).unwrap();
        let e = get_name(&snmp_oid).unwrap_err();
        assert_eq!(e.to_string(), "SNMP OID too long");
        #[cfg(not(feature = "dynamic"))]
        {
            let e = get_type(&snmp_oid).unwrap_err();
            assert_eq!(e.to_string(), "SNMP OID too long");
        }
    }
}
