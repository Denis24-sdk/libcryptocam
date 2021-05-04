use crate::decrypt::{DecryptingJob, ProgressCallback};
use anyhow::{bail, Result};
use serde::Deserialize;
use std::{
    fs::File,
    io::{copy, Read},
    path::PathBuf,
    str,
    sync::{atomic::AtomicBool, Arc},
};

pub fn build_image_decryption_job(
    data: Box<dyn Read>,
    metadata: &[u8],
    out_path: PathBuf,
    total_file_size: u64,
    bytes_before_data: u64,
) -> Result<Box<dyn DecryptingJob + Send>> {
    let metadata = parse_metadata(str::from_utf8(metadata)?)?;
    Ok(Box::new(ImageDecryptionJob {
        params: ImageDecryptionJobParams {
            data,
            metadata,
            out_path,
            total_file_size,
            bytes_before_data,
        },
    }))
}

struct ImageDecryptionJob {
    params: ImageDecryptionJobParams,
}

struct ImageDecryptionJobParams {
    data: Box<dyn Read>,
    metadata: ImageMetadata,
    out_path: PathBuf,
    total_file_size: u64,
    bytes_before_data: u64,
}

unsafe impl Send for ImageDecryptionJob {}

impl DecryptingJob for ImageDecryptionJob {
    fn run(&mut self, progress_callback: Box<&mut dyn ProgressCallback>, _cancel: Arc<AtomicBool>) {
        let bytes_before_data = self.params.bytes_before_data;
        let total_file_size = self.params.total_file_size;
        progress_callback.set_total_file_size(total_file_size);
        progress_callback.set_offset(bytes_before_data);

        let filename = format!(
            "{}.{}",
            self.params.metadata.timestamp, self.params.metadata.format
        );
        let out_path = &mut self.params.out_path;
        out_path.push(filename);
        let mut out = match File::create(&out_path) {
            Err(e) => {
                progress_callback.on_error(e.into());
                return;
            }
            Ok(f) => f,
        };
        match copy(&mut self.params.data, &mut out) {
            Ok(_) => {}
            Err(e) => {
                progress_callback.on_error(Box::new(e));
                return;
            }
        };
        progress_callback.on_complete();
    }
}

fn parse_metadata(json: &str) -> Result<ImageMetadata> {
    let metadata: ImageMetadata = match serde_json::from_str(json) {
        Ok(m) => m,
        Err(e) => bail!("Error parsing metadata: {}", e),
    };
    Ok(metadata)
}

#[derive(Debug, Deserialize)]
struct ImageMetadata {
    timestamp: String,
    format: String,
}
