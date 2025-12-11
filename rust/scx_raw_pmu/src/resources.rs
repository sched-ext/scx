use include_dir::{include_dir, Dir};
use std::borrow::Cow;
use std::fs;
use std::io;
use std::path::PathBuf;

static ARCH_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/arch");

#[derive(Debug)]
pub(crate) enum ResourceDir {
    Embedded(&'static Dir<'static>),
    Filesystem(PathBuf),
}

impl Default for ResourceDir {
    fn default() -> Self {
        ResourceDir::Embedded(&ARCH_DIR)
    }
}

#[derive(Debug)]
pub(crate) enum ResourceFile {
    Embedded(&'static include_dir::File<'static>),
    Filesystem { name: String, full_path: PathBuf },
}

impl ResourceFile {
    pub fn path(&self) -> &str {
        match self {
            ResourceFile::Embedded(file) => file.path().to_str().unwrap(),
            ResourceFile::Filesystem { name, .. } => name,
        }
    }

    pub fn read(&self) -> io::Result<Cow<'static, [u8]>> {
        match self {
            ResourceFile::Embedded(file) => Ok(Cow::Borrowed(file.contents())),
            ResourceFile::Filesystem { full_path, .. } => {
                let contents = fs::read(full_path)?;
                Ok(Cow::Owned(contents))
            }
        }
    }
}

impl ResourceDir {
    pub(crate) fn new_filesystem(path: PathBuf) -> Self {
        ResourceDir::Filesystem(path)
    }

    pub(crate) fn get_file(&self, path: &str) -> io::Result<ResourceFile> {
        match self {
            ResourceDir::Embedded(dir) => {
                let full_path = dir.path().join(path);
                let file = ARCH_DIR
                    .get_file(full_path.to_str().unwrap())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "file not found in embedded resources",
                        )
                    })?;
                Ok(ResourceFile::Embedded(file))
            }
            ResourceDir::Filesystem(base_path) => {
                let full_path = base_path.join(path);
                if full_path.is_file() {
                    let name = path.to_string();
                    Ok(ResourceFile::Filesystem { name, full_path })
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("file not found: {}", full_path.display()),
                    ))
                }
            }
        }
    }

    pub(crate) fn get_dir(&self, path: &str) -> io::Result<ResourceDir> {
        match self {
            ResourceDir::Embedded(dir) => {
                let full_path = dir.path().join(path);
                let subdir = ARCH_DIR
                    .get_dir(full_path.to_str().unwrap())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "directory not found in embedded resources",
                        )
                    })?;
                Ok(ResourceDir::Embedded(subdir))
            }
            ResourceDir::Filesystem(base_path) => {
                let full_path = base_path.join(path);
                if full_path.is_dir() {
                    Ok(ResourceDir::Filesystem(full_path))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("directory not found: {}", full_path.display()),
                    ))
                }
            }
        }
    }

    pub(crate) fn files(&self) -> io::Result<Vec<ResourceFile>> {
        match self {
            ResourceDir::Embedded(dir) => {
                let mut files = Vec::new();
                for file in dir.files() {
                    files.push(ResourceFile::Embedded(file));
                }
                Ok(files)
            }
            ResourceDir::Filesystem(base_path) => {
                let mut files = Vec::new();
                for entry in fs::read_dir(base_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        let name = path.file_name().unwrap().to_str().unwrap().to_string();
                        files.push(ResourceFile::Filesystem {
                            name,
                            full_path: path,
                        });
                    }
                }
                Ok(files)
            }
        }
    }
}
