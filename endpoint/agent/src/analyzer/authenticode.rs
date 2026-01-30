use std::ffi::c_void;

use windows::Win32::{Foundation::{HANDLE, HWND}, Security::{Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, CertGetNameStringW}}}; 
use windows::Win32::Security::WinTrust::{CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperProvDataFromStateData, WinVerifyTrust}; 
use windows::core::{PCWSTR, PWSTR};


pub struct SignatureStatus {
    pub is_signed: bool,
    pub is_trusted: bool,
    pub signer: Option<String>,
    pub is_revoked: bool
}

pub fn verify_signature(file_path: &str) -> SignatureStatus {
    let wide_path: Vec<u16> = file_path.encode_utf16().chain(std::iter::once(0)).collect();
    let pcwstr_path = PCWSTR(wide_path.as_ptr());

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: pcwstr_path,
        hFile: HANDLE(std::ptr::null_mut()),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 { pFile: &mut file_info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE(std::ptr::null_mut()),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: windows::Win32::Security::WinTrust::WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut win_trust_data as *mut _ as *mut c_void,
        )
    };

    let is_trusted = status == 0;
    let is_signed = status as u32 != 0x800B0100;//0x800B0100 => TRUST_E_NOSIGNATURE 
    let is_revoked = status as u32 == 0x800B010C;// 0x800B010C => CERT_E_REVOKED

    let mut signer_name = None;

    if is_signed {
        signer_name = unsafe {get_signer_name(win_trust_data.hWVTStateData)}
    }

    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut win_trust_data as *mut _ as *mut c_void,
        );
    }
    

    SignatureStatus {
        is_signed,
        is_trusted,
        is_revoked,
        signer: signer_name,
    }
}

unsafe fn get_signer_name(state_data: HANDLE) -> Option<String> {
    if state_data.is_invalid() || state_data.0.is_null() {
        return None;
    }

    let prov_data: *mut CRYPT_PROVIDER_DATA = unsafe{WTHelperProvDataFromStateData(state_data)};
    if prov_data.is_null() {
        return None;
    }

    let signers = unsafe{(*prov_data).pasSigners};
    if signers.is_null() || unsafe{(*prov_data).csSigners == 0} {
        return None;
    }

    let signer: &CRYPT_PROVIDER_SGNR = unsafe{&*signers.offset(0)};

    let chain = signer.pasCertChain;
    if chain.is_null() || signer.csCertChain == 0 {
        return None;
    }

    let cert_node: &CRYPT_PROVIDER_CERT = unsafe {&*chain.offset(0)};
    let cert_context = cert_node.pCert;

    if cert_context.is_null() {
        return None;
    }

    let len = unsafe {CertGetNameStringW(
        cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_STR_ENABLE_PUNYCODE_FLAG,
        None,
        None
    )};

    if len == 0 {
        return None;
    }

    let mut buffer = vec![0u16; len as usize];
    let res = unsafe {CertGetNameStringW(
        cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_STR_ENABLE_PUNYCODE_FLAG,
        None,
        Some(&mut buffer)
    )};

    if res == 0 {
        None
    } else {
        if let Some(last) = buffer.last() {
            if *last == 0 {
                buffer.pop();
            }
        }
        String::from_utf16(&buffer).ok()
    }
}