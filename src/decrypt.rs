use crate::{keyring::Keyring, parser::parse_header};
use ac_ffmpeg::{
    codec::{audio::ChannelLayout, AudioCodecParameters, CodecParameters, VideoCodecParameters},
    format::{
        io::IO,
        muxer::{Muxer, OutputFormat},
    },
    packet::{Packet, PacketMut},
    time::Timestamp,
};
use anyhow::{anyhow, bail, Result};
use bytes::{ByteOrder, LittleEndian};
use log::{debug, warn};
use serde::Deserialize;
use std::{
    error::Error, fs::File, io::BufReader, io::Read, path::PathBuf, str, sync::atomic::AtomicBool,
    sync::Arc,
};

#[derive(Debug, Deserialize)]
struct VideoMetadata {
    width: usize,
    height: usize,
    rotation: u16,
    video_bitrate: u64,
    audio_sample_rate: u32,
    audio_channel_count: u32,
    audio_bitrate: u64,
    timestamp: String,
}

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
    let metadata = parse_video_metadata(str::from_utf8(&metadata_bytes)?)?;
    Ok(Box::new(VideoMuxingJob {
        params: Box::new(VideoMuxingJobParams {
            data: Box::new(decrypted),
            metadata,
            out_path,
            total_file_size,
            bytes_before_data: header_len + offset_to_data as u64,
        }),
    }))
}

fn parse_video_metadata(json: &str) -> Result<VideoMetadata> {
    let metadata: VideoMetadata = match serde_json::from_str(json) {
        Ok(m) => m,
        Err(e) => bail!("Error parsing metadata: {}", e),
    };
    Ok(metadata)
}

#[derive(Debug, PartialEq)]
enum PacketType {
    Video,
    Audio,
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

struct VideoMuxingJobParams {
    data: Box<dyn Read>,
    metadata: VideoMetadata,
    out_path: PathBuf,
    total_file_size: u64,
    bytes_before_data: u64,
}

struct VideoMuxingJob {
    params: Box<VideoMuxingJobParams>,
}

unsafe impl Send for VideoMuxingJob {}

impl DecryptingJob for VideoMuxingJob {
    fn run(&mut self, progress_callback: Box<&mut dyn ProgressCallback>, cancel: Arc<AtomicBool>) {
        let bytes_before_data = self.params.bytes_before_data;
        let total_file_size = self.params.total_file_size;
        progress_callback.set_total_file_size(total_file_size);
        progress_callback.set_offset(bytes_before_data);
        mux_video(
            &mut self.params.data,
            &self.params.metadata,
            &mut self.params.out_path,
            progress_callback,
            cancel,
        )
    }
}

fn mux_video(
    data: &mut dyn Read,
    metadata: &VideoMetadata,
    out_path: &mut PathBuf,
    progress_callback: Box<&mut dyn ProgressCallback>,
    cancel: Arc<AtomicBool>,
) {
    let video_params = VideoCodecParameters::builder("h264")
        .unwrap()
        .width(metadata.width)
        .height(metadata.height)
        .bit_rate(metadata.video_bitrate)
        .build();
    let channel_layout = match ChannelLayout::from_channels(metadata.audio_channel_count as u32) {
        None => {
            progress_callback.on_error(anyhow!("Error getting channel layout").into());
            return;
        }
        Some(c) => c,
    };
    let audio_params = AudioCodecParameters::builder("aac")
        .unwrap()
        .channel_layout(channel_layout)
        .bit_rate(metadata.audio_bitrate)
        .sample_rate(metadata.audio_sample_rate)
        .build();
    let file_name = format!("{}.mp4", metadata.timestamp);
    let output_format = match OutputFormat::guess_from_file_name(&file_name) {
        None => {
            progress_callback.on_error(
                anyhow!("Could not find output format for filename {}", file_name).into(),
            );
            return;
        }
        Some(o) => o,
    };
    out_path.push(file_name);
    let out = match File::create(&out_path) {
        Err(e) => {
            progress_callback.on_error(e.into());
            return;
        }
        Ok(f) => f,
    };
    let io = IO::from_seekable_write_stream(out);
    let mut muxer_builder = Muxer::builder().interleaved(true);
    let video_stream_index = muxer_builder
        .add_stream(&CodecParameters::from(video_params))
        .unwrap();
    let audio_stream_index = muxer_builder
        .add_stream(&CodecParameters::from(audio_params))
        .unwrap();
    let mut muxer = match muxer_builder
        .set_stream_option(video_stream_index, "rotate", metadata.rotation)
        .build(io, output_format)
    {
        Err(e) => {
            progress_callback.on_error(e.into());
            return;
        }
        Ok(m) => m,
    };

    // packet header contains packet type (1B), pts in us (8B), length (4B)
    let mut packet_header: [u8; 13] = [0; 13];
    let mut first_pts: Option<i64> = None;
    let mut progress: u64 = 0;
    while let Ok(()) = data.read_exact(&mut packet_header) {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let packet_type = match packet_header[0] {
            1 => PacketType::Video,
            2 => PacketType::Audio,
            e => {
                warn!("Unknown packet type {}", e);
                continue;
            }
        };
        let pts = LittleEndian::read_u64(&packet_header[1..9]);
        let packet_length = LittleEndian::read_u32(&packet_header[9..13]) as usize;
        let mut packet_data = vec![0; packet_length];
        match data.read_exact(&mut packet_data) {
            Err(e) => {
                progress_callback.on_error(e.into());
                return;
            }
            Ok(()) => {}
        };
        if first_pts.is_none() {
            first_pts = Some(pts as i64);
        }
        let packet: Packet = PacketMut::from(packet_data)
            .with_pts(Timestamp::from_micros(pts as i64 - first_pts.unwrap()))
            .with_stream_index(match packet_type {
                PacketType::Video => video_stream_index as usize,
                PacketType::Audio => audio_stream_index as usize,
            })
            .freeze();
        match muxer.push(packet) {
            Err(e) => {
                progress_callback.on_error(e.into());
                return;
            }
            Ok(()) => {}
        };
        progress += packet_header.len() as u64 + packet_length as u64;
        progress_callback.on_progress(progress);
    }
    match muxer.flush() {
        Err(e) => {
            progress_callback.on_error(e.into());
            return;
        }
        Ok(()) => {}
    };
    progress_callback.on_complete();
}
