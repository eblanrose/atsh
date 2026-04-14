use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use directories_next::ProjectDirs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub key_files: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        let set = HashSet::new();

        Self {
            key_files: set,
        }
    }
}


pub fn config_path() -> Option<PathBuf> {
    let proj = ProjectDirs::from("not", "atunnel", "notatunnel-server")?;
    Some(proj.config_dir().to_path_buf())
}

pub fn data_path() -> Option<PathBuf> {
    let proj = ProjectDirs::from("not", "atunnel", "notatunnel-server")?;
    Some(proj.data_dir().to_path_buf())
}


pub fn json_path(dir: Option<PathBuf>) -> Option<PathBuf> {
    dir.map(|mut p| {
        p.push("config.json");
        p
    })
}

pub fn keys_path(dir: Option<PathBuf>) -> Option<PathBuf> {
    dir.map(|mut p| {
        p.push("keys");
        p
    })
}

pub fn load_keys(
    key_files: &HashSet<String>,
    config_path: Option<PathBuf>,
) -> std::io::Result<HashSet<Vec<u8>>> {
    let mut result: HashSet<Vec<u8>> = HashSet::new();

    let base = match config_path {
        Some(p) => p.join("keys"),
        None => return Ok(result),
    };

    for file_name in key_files {
        let full_path = base.join(file_name);

        let data = fs::read(&full_path)?;
        result.insert(data);
    }

    Ok(result)
}

impl Config {
    pub fn load(path: &str) -> Self {
        let data = fs::read_to_string(path);

        match data {
            Ok(content) => {
                let parsed: Result<Config, _> = serde_json::from_str(&content);

                parsed.unwrap_or_else(|_| {
                    eprintln!("config is weirdz");
                    Config::default()
                })
            }
            Err(_) => {
                eprintln!("file not found");
                Config::default()
            }
        }
    }

    pub fn save(&self, path: &str) {
        let json = serde_json::to_string_pretty(self)
            .expect("cant serialize cfg");

        fs::write(path, json)
            .expect("cant write to cfg");
    }

    pub fn add_key(&mut self, key: &str) {
        self.key_files.insert(key.to_string());
    }
}