use crate::decrypt::{DecryptingJob, ProgressCallback};
use ac_ffmpeg::{
    codec::{
        audio::ChannelLayout, bsf::BitstreamFilter, AudioCodecParameters, CodecParameters,
        VideoCodecParameters,
    },
    format::{
        io::IO,
        muxer::{Muxer, OutputFormat},
    },
    packet::{Packet, PacketMut},
    time::Timestamp,
};
use anyhow::{anyhow, bail, Result};
use bytes::{ByteOrder, LittleEndian};
use log::warn;
use serde::Deserialize;
use std::{fs::File, io::Read, path::PathBuf, str, sync::atomic::AtomicBool, sync::Arc};

pub fn build_video_decryption_job(
    data: Box<dyn Read>,
    metadata: &[u8],
    out_path: PathBuf,
    total_file_size: u64,
    bytes_before_data: u64,
) -> Result<Box<dyn DecryptingJob + Send>> {
    let metadata = parse_video_metadata(str::from_utf8(metadata)?)?;
    Ok(Box::new(VideoMuxingJob {
        params: VideoMuxingJobParams {
            data,
            metadata,
            out_path,
            total_file_size,
            bytes_before_data,
        },
    }))
}

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
    #[serde(default)]
    codec: Option<String>,
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

struct VideoMuxingJobParams {
    data: Box<dyn Read>,
    metadata: VideoMetadata,
    out_path: PathBuf,
    total_file_size: u64,
    bytes_before_data: u64,
}

struct VideoMuxingJob {
    params: VideoMuxingJobParams,
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
    // 1. Определение кодека (HEVC или AVC)
    let codec_name = match metadata.codec.as_deref() {
        Some(c) if c.eq_ignore_ascii_case("hevc") || c.eq_ignore_ascii_case("h265") => "hevc",
        _ => "h264",
    };

    let video_params = VideoCodecParameters::builder(codec_name)
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
        .channel_layout(&channel_layout)
        .bit_rate(metadata.audio_bitrate)
        .sample_rate(metadata.audio_sample_rate)
        .build();

    // 2. Создаем фильтр для исправления аудио (FIX ДЛЯ WINDOWS)
    let mut audio_bsf = match BitstreamFilter::from_name("aac_adtstoasc") {
        Ok(bsf) => bsf,
        Err(e) => {
            progress_callback.on_error(anyhow!("Error creating audio filter: {}", e).into());
            return;
        }
    };
    // Фильтру нужно знать параметры входящего аудио
    if let Err(e) = audio_bsf.set_parameters(CodecParameters::from(audio_params.clone())) {
        progress_callback.on_error(anyhow!("Error setting audio filter params: {}", e).into());
        return;
    }

    let file_name = format!("{}.mp4", metadata.timestamp.replace(":", "-"));
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

    let video_stream_index = match muxer_builder.add_stream(&CodecParameters::from(video_params)) {
        Ok(i) => i,
        Err(e) => {
             progress_callback.on_error(anyhow!("Error adding video stream: {}", e).into());
             return;
        }
    };

    let audio_stream_index = match muxer_builder.add_stream(&CodecParameters::from(audio_params)) {
        Ok(i) => i,
        Err(e) => {
             progress_callback.on_error(anyhow!("Error adding audio stream: {}", e).into());
             return;
        }
    };

    // 3. Исправление поворота (FIX ДЛЯ ORIENTATION)
    // Преобразуем число в строку явно
    muxer_builder.streams_mut()[video_stream_index]
        .set_metadata("rotate", &metadata.rotation.to_string());

    let mut muxer = match muxer_builder.build(io, output_format) {
        Err(e) => {
            progress_callback.on_error(e.into());
            return;
        }
        Ok(m) => m,
    };

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

        let packet = PacketMut::from(packet_data)
            .with_pts(Timestamp::from_micros(pts as i64 - first_pts.unwrap()))
            .with_stream_index(match packet_type {
                PacketType::Video => video_stream_index as usize,
                PacketType::Audio => audio_stream_index as usize,
            })
            .freeze();

        // 4. Обработка пакетов с учетом фильтра для Аудио
        match packet_type {
            PacketType::Audio => {
                // Прогоняем аудио через фильтр aac_adtstoasc
                if let Err(e) = audio_bsf.push(packet) {
                     progress_callback.on_error(anyhow!("Error pushing to audio filter: {}", e).into());
                     return;
                }
                // Забираем отфильтрованные пакеты (их может быть несколько или 0)
                while let Ok(Some(filtered_packet)) = audio_bsf.take() {
                    if let Err(e) = muxer.push(filtered_packet) {
                        progress_callback.on_error(e.into());
                        return;
                    }
                }
            },
            PacketType::Video => {
                // Видео пишем как есть
                if let Err(e) = muxer.push(packet) {
                    progress_callback.on_error(e.into());
                    return;
                }
            }
        }

        progress += packet_header.len() as u64 + packet_length as u64;
        progress_callback.on_progress(progress);
    }

    // Сбрасываем остатки фильтра
    if let Err(e) = audio_bsf.flush() {
         progress_callback.on_error(anyhow!("Error flushing audio filter: {}", e).into());
         return;
    }
    while let Ok(Some(filtered_packet)) = audio_bsf.take() {
        if let Err(e) = muxer.push(filtered_packet) {
            progress_callback.on_error(e.into());
            return;
        }
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