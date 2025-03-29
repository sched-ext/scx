use csv::ReaderBuilder;
use rev_buf_reader::RevBufReader;
use serde::Deserialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct SystemData {
    pub os: String,
    pub cpu: String,
    pub gpu: String,
    pub ram: u64,
    pub kernel: String,
    pub driver: String,
    pub cpu_scheduler: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrameData {
    pub fps: f64,
    pub frametime: f64,
    pub cpu_load: f64,
    pub cpu_power: f64,
    pub gpu_load: f64,
    pub cpu_temp: f64,
    pub gpu_temp: f64,
    pub gpu_core_clock: f64,
    pub gpu_mem_clock: f64,
    pub gpu_vram_used: f64,
    pub gpu_power: f64,
    pub ram_used: f64,
    pub swap_used: f64,
    pub process_rss: f64,
    pub elapsed: u64,
}

pub struct MangoHudTailer {
    pub system_data: SystemData,
    frame_buffer: VecDeque<FrameData>,
    capacity: usize,
    csv_path: PathBuf,
}

impl MangoHudTailer {
    pub fn new<P: AsRef<Path>>(csv_path: P, capacity: usize) -> Self {
        Self {
            system_data: SystemData {
                os: String::new(),
                cpu: String::new(),
                gpu: String::new(),
                ram: 0,
                kernel: String::new(),
                driver: String::new(),
                cpu_scheduler: String::new(),
            },
            frame_buffer: VecDeque::with_capacity(capacity),
            capacity,
            csv_path: csv_path.as_ref().to_path_buf(),
        }
    }

    pub fn init(&mut self) -> std::io::Result<()> {
        let file = File::open(&self.csv_path)?;
        let mut lines = BufReader::new(file).lines();

        let _ = lines.next();

        if let Some(Ok(system_line)) = lines.next() {
            let mut sys_reader = ReaderBuilder::new()
                .has_headers(false)
                .from_reader(system_line.as_bytes());

            for result in sys_reader.deserialize::<SystemData>() {
                match result {
                    Ok(sys_data) => {
                        self.system_data = sys_data;
                    }
                    Err(e) => {
                        eprintln!("Could not parse system data: {e}");
                    }
                }
            }
        }

        let _ = lines.next();

        for line_result in lines {
            if let Ok(line) = line_result {
                if line.trim().is_empty() {
                    continue;
                }

                let mut rdr = ReaderBuilder::new()
                    .has_headers(false)
                    .from_reader(line.as_bytes());

                for record in rdr.deserialize::<FrameData>() {
                    match record {
                        Ok(frame) => {
                            self.push_frame(frame);
                        }
                        Err(e) => {
                            eprintln!("Could not parse frame data: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
    ///
    /// Read latest framedata
    ///
    pub fn read_latest(&mut self, n: usize) -> std::io::Result<()> {
        let file = File::open(&self.csv_path)?;
        let rev_reader = RevBufReader::new(file);

        let mut new_lines = Vec::new();

        for line_result in rev_reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading line from bottom: {e}");
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }

            if new_lines.len() < n {
                new_lines.push(line);
            } else {
                break;
            }
        }

        // reverse so time order
        new_lines.reverse();

        for line in new_lines {
            let mut rdr = ReaderBuilder::new()
                .has_headers(false)
                .from_reader(line.as_bytes());

            for result in rdr.deserialize::<FrameData>() {
                match result {
                    Ok(frame) => {
                        self.push_frame(frame);
                    }
                    Err(e) => {
                        eprintln!("Could not parse frame data: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    fn push_frame(&mut self, frame: FrameData) {
        if self.frame_buffer.len() == self.capacity {
            self.frame_buffer.pop_front();
        }
        self.frame_buffer.push_back(frame);
    }
    ///
    /// Get framedata read
    ///
    pub fn get_framedata(&self) -> Vec<FrameData> {
        self.frame_buffer.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mangohud_tailer() -> std::io::Result<()> {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("test/fps-data.csv");
        // frametime is unique per row in the test data
        let last_test_frame_time = 15.6854;

        let mut reader = MangoHudTailer::new(test_file, 100);
        reader.init()?;

        println!("System Data: {:?}", reader.system_data);

        let initial_frames = reader.get_framedata();
        println!("Initial frames: {:#?}", initial_frames);

        assert_eq!(
            initial_frames[initial_frames.len() - 1].frametime,
            last_test_frame_time
        );

        reader.read_latest(2)?;

        let updated_frames = reader.get_framedata();
        println!("Updated frames: {:#?}", updated_frames);

        assert_eq!(
            updated_frames[updated_frames.len() - 1].frametime,
            last_test_frame_time
        );
        assert_eq!(
            updated_frames[updated_frames.len() - 3].frametime,
            last_test_frame_time
        );

        Ok(())
    }
}
