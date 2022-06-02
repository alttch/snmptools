use std::env;
use std::ffi::{CStr, CString};
use std::fmt;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ErrorKind {
    Failed,
    InvalidData,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ErrorKind::Failed => "Function failed",
                ErrorKind::InvalidData => "Invalid data",
            }
        )
    }
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    fn invalid_data(msg: impl fmt::Display) -> Self {
        Self {
            kind: ErrorKind::InvalidData,
            message: msg.to_string(),
        }
    }
    fn failed(msg: impl fmt::Display) -> Self {
        Self {
            kind: ErrorKind::Failed,
            message: msg.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

const MAX_NAME_LEN: usize = 1024;

#[derive(Default, Clone)]
pub struct Config<'a> {
    mibs: &'a [&'a str],
    mib_dirs: &'a [&'a str],
}

impl<'a> Config<'a> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
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
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
///
/// # Panics
///
/// Should not panic
pub unsafe fn init(config: &Config) {
    if !config.mibs.is_empty() {
        env::set_var("MIBS", config.mibs.join(":"));
    }
    if !config.mib_dirs.is_empty() {
        env::set_var("MIBDIRS", config.mib_dirs.join(":"));
    }
    let app_name: CString = CString::new("eva-common").unwrap();
    netsnmp_sys::init_snmp(app_name.as_ptr());
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
pub unsafe fn get_name(snmp_oid: &der_parser::oid::Oid) -> Result<String, Error> {
    let mut n_oid: [netsnmp_sys::oid; netsnmp_sys::MAX_OID_LEN] = [0; netsnmp_sys::MAX_OID_LEN];
    let mut n_len = 0;
    for (n, val) in snmp_oid.iter_bigint().enumerate() {
        if n > netsnmp_sys::MAX_OID_LEN {
            return Err(Error::invalid_data("SNMP OID too long"));
        }
        n_oid[n] = val
            .try_into()
            .map_err(|e| Error::failed(format!("Invalid SNMP OID: {}", e)))?;
        n_len += 1;
    }
    let mut name_buf = [0_i8; MAX_NAME_LEN];
    netsnmp_sys::snprint_objid(
        name_buf.as_mut_ptr(),
        MAX_NAME_LEN,
        n_oid.as_slice().as_ptr(),
        n_len,
    );
    let name = CStr::from_ptr(name_buf.as_mut_ptr());
    Ok(name.to_string_lossy().to_string())
}

/// # Safety
///
/// Should not have safety problems unless netsnmp bugs are found
pub unsafe fn get_oid(name: &str) -> Result<der_parser::oid::Oid, Error> {
    let mut n_oid: [netsnmp_sys::oid; netsnmp_sys::MAX_OID_LEN] = [0; netsnmp_sys::MAX_OID_LEN];
    let c_name = CString::new(name).map_err(Error::invalid_data)?;
    let mut len = netsnmp_sys::MAX_OID_LEN;
    let res = netsnmp_sys::get_node(c_name.as_ptr(), n_oid.as_mut_ptr(), &mut len);
    if res == 1 {
        der_parser::oid::Oid::from(&n_oid[..len])
            .map_err(|_| Error::failed("Unable to create SNMP OID"))
    } else {
        dbg!(res, len);
        Err(Error::failed("Unable to get SNMP OID"))
    }
}

#[cfg(test)]
mod test {
    use super::{get_name, get_oid, init, Config};
    #[test]
    fn test_mib() {
        unsafe {
            init(&Config::new().mibs(&["./ibmConvergedPowerSystems.mib"]));
        }
        let snmp_oid = der_parser::oid::Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
        let name = unsafe { get_name(&snmp_oid).unwrap() };
        let snmp_oid2 = unsafe { get_oid(&name) }.unwrap();
        assert_eq!(snmp_oid, snmp_oid2);
    }
}
