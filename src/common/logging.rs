use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Mutex, Once};
use std::fmt;

// Global static logger
static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);
static INIT: Once = Once::new();
pub struct Logger {
    file: File,
}

impl Logger {
    pub fn init(path: impl AsRef<Path>) -> io::Result<()> {
        INIT.call_once(|| {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(path)
                .expect("Failed to open log file");
            
            let logger = Logger { file };
            *LOGGER.lock().unwrap() = Some(logger);
        });
        
        Ok(())
    }

    /// Check if the logger has been initialized
    pub fn is_initialized() -> bool {
        if let Ok(logger_guard) = LOGGER.lock() {
            return logger_guard.is_some();
        }
        false
    }
}

pub fn log(message: impl fmt::Debug) -> io::Result<()> {
    if let Ok(mut logger_guard) = LOGGER.lock() {
        if let Some(logger) = logger_guard.as_mut() {
            let formatted = format!("{:#?}\n", message);
            logger.file.write_all(formatted.as_bytes())?;
            logger.file.flush()?;
        } else {
            eprintln!("Warning: Logger not initialized. Call Logger::init() first. Message not logged: {:?}", message);
        }
    }
    Ok(())
}
