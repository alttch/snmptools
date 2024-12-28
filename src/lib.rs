#![ doc = include_str!( concat!( env!( "CARGO_MANIFEST_DIR" ), "/", "README.md" ) ) ]
#[cfg(not(feature = "dynamic"))]
extern crate netsnmp_sys_nocrypto;

pub use der_parser::oid::Oid;
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
            #[cfg(feature = "dynamic")]
            lib_path: "libnetsnmp.so",
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
        env::set_var("MIBS", config.mibs.join(":"));
    }
    if !config.mib_dirs.is_empty() {
        env::set_var("MIBDIRS", config.mib_dirs.join(":"));
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
    #[cfg(not(feature = "dynamic"))]
    const MAX_OID_LEN: usize = netsnmp_sys::MAX_OID_LEN;

    #[cfg(feature = "dynamic")]
    let mut n_oid: [u64; MAX_OID_LEN] = [0; MAX_OID_LEN];
    #[cfg(not(feature = "dynamic"))]
    let mut n_oid: [netsnmp_sys::oid; MAX_OID_LEN] = [0; MAX_OID_LEN];

    let mut n_len = 0;
    for (n, val) in snmp_oid.iter_bigint().enumerate() {
        if n > MAX_OID_LEN {
            return Err(Error::invalid_data("SNMP OID too long"));
        }
        n_oid[n] = val
            .try_into()
            .map_err(|e| Error::failed(format!("Invalid SNMP OID: {}", e)))?;
        n_len += 1;
    }
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
    let name = unsafe { CStr::from_ptr(name_buf.as_mut_ptr().cast_const()) };
    Ok(name.to_string_lossy().to_string())
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
///
/// # Panics
///
/// Will panic if not initialized
pub fn get_oid(name: &str) -> Result<Oid, Error> {
    #[cfg(not(feature = "dynamic"))]
    const MAX_OID_LEN: usize = netsnmp_sys::MAX_OID_LEN;

    #[cfg(feature = "dynamic")]
    let mut n_oid: [u64; MAX_OID_LEN] = [0; MAX_OID_LEN];
    #[cfg(not(feature = "dynamic"))]
    let mut n_oid: [netsnmp_sys::oid; MAX_OID_LEN] = [0; MAX_OID_LEN];

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

#[cfg(test)]
mod test {
    use super::{get_name, get_oid, init, Config, Oid};
    #[cfg(not(feature = "dynamic"))]
    #[test]
    fn test_mib() {
        init(&Config::new().mibs(&["./ibmConvergedPowerSystems.mib"])).unwrap();
        let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
        let name = get_name(&snmp_oid).unwrap();
        assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
        let snmp_oid2 = get_oid(&name).unwrap();
        assert_eq!(snmp_oid, snmp_oid2);
    }
    #[cfg(feature = "dynamic")]
    #[test]
    fn test_mib_dynamic() {
        init(&Config::new().mibs(&["./ibmConvergedPowerSystems.mib"])).unwrap();
        let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
        let name = get_name(&snmp_oid).unwrap();
        assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
        let snmp_oid2 = get_oid(&name).unwrap();
        assert_eq!(snmp_oid, snmp_oid2);
    }
}
