 use crate::config::AddressType;

//use with bdk_wallet::descriptor::ExtendedDescriptor
// for valid descriptors
pub(crate) fn get_address_type(descriptor: &str) -> AddressType {
    if descriptor.contains("pkh(") {
        AddressType::P2pkh
    } else if descriptor.contains("wpkh(") {
        AddressType::P2wpkh
    } else if descriptor.contains("sh(") {
        AddressType::P2sh
    } else if descriptor.contains("tr(") {
        AddressType::P2tr
    } else if descriptor.contains("wsh(") {
        AddressType::P2wsh
    } else {
        AddressType::P2pkh
    }
}