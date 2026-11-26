//! AAD construction per docs/CRYPTOGRAPHY.md §4.2 (revision 2).

pub const DOMAIN: &[u8; 8] = b"VELFORT\0";
pub const FORMAT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    HeaderWrap = 0x01,
    ItemSummary = 0x10,
    ItemPayload = 0x11,
    ItemHistory = 0x12,
    Folder = 0x20,
    Settings = 0x30,
    Manifest = 0x40,
    AttachMeta = 0x50,
    AttachChunk = 0x51,
}

pub struct Aad<'a> {
    pub vault_id: [u8; 16],
    pub purpose: Purpose,
    pub record_id: [u8; 16],
    pub revision: u64,
    pub extra: &'a [u8],
}

impl Aad<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 2 + 16 + 1 + 16 + 8 + 4 + self.extra.len());
        v.extend_from_slice(DOMAIN);
        v.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        v.extend_from_slice(&self.vault_id);
        v.push(self.purpose as u8);
        v.extend_from_slice(&self.record_id);
        v.extend_from_slice(&self.revision.to_le_bytes());
        // length-prefixed variable part => unambiguous encoding
        v.extend_from_slice(&(self.extra.len() as u32).to_le_bytes());
        v.extend_from_slice(self.extra);
        v
    }
}
