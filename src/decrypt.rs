use crate::{
    decrypt_image::build_image_decryption_job, decrypt_video::build_video_decryption_job,
    keyring::Keyring, parser::parse_header,
};
use anyhow::{bail, Result};
use bytes::ByteOrder;
use std::{
    error::Error, fs::File, io::BufReader, io::Read, path::PathBuf, sync::atomic::AtomicBool,
    sync::Arc,
};

/// Decrypts a Cryptocam output file, taking keys from the provided keyring.
/// passphrase_input is used to ask the user for a passphrase through e.g. pinentry or the terminal.
/// progress_callback(process, total) receives the number of processed bytes and the total length of the file.
pub fn decrypt(
    file: File,
    keyring: &mut Keyring,
    out_path: PathBuf,
) -> Result<Box<dyn DecryptingJob + Send>> {
    let total_file_size = file.metadata().map_or(0, |md| md.len());
    let mut buf_reader = BufReader::new(file);
    let (header, header_len) = parse_header(&mut buf_reader)?;
    if header.version != 1 {
        bail!("Bad Version in file header")
    }
    let mut decrypted =
        BufReader::new(keyring.decrypt(Box::new(buf_reader), &header.recipient_digests)?);
    let mut encrypted_header: [u8; 5] = [0; 5];
    decrypted.read_exact(&mut encrypted_header)?;
    let file_type = encrypted_header[0];
    let offset_to_data = bytes::LittleEndian::read_u32(&encrypted_header[1..5]);
    let bytes_before_metadata: usize = encrypted_header.len();
    let metadata_len: usize = offset_to_data as usize - bytes_before_metadata;
    let mut metadata_bytes = vec![0; metadata_len];
    decrypted.read_exact(&mut metadata_bytes)?;
    match file_type {
        1 => build_video_decryption_job(
            Box::new(decrypted),
            metadata_bytes.as_slice(),
            out_path,
            total_file_size,
            header_len + offset_to_data as u64,
        ),
        2 => build_image_decryption_job(
            Box::new(decrypted),
            metadata_bytes.as_slice(),
            out_path,
            total_file_size,
            header_len + offset_to_data as u64,
        ),
        other => {
            bail!("Unknown file type {}", other);
        }
    }
}

pub trait DecryptingJob {
    fn run(&mut self, progress_callback: Box<&mut dyn ProgressCallback>, cancel: Arc<AtomicBool>);
}

pub trait ProgressCallback {
    fn set_total_file_size(&mut self, n: u64);
    // bytes in the headers before actual data, these have to be added to processed_bytes to calculate progress
    fn set_offset(&mut self, offset: u64);
    fn on_progress(&mut self, processed_bytes: u64);
    fn on_complete(&mut self);
    fn on_error(&mut self, error: Box<dyn Error>);
}
