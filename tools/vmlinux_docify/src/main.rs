use clap::{ColorChoice, Parser};
use std::collections::HashMap;
use std::fs;
use std::process;

/// A tool to annotate vmlinux.h with documentation from kernel sources
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = "A tool to annotate vmlinux.h with documentation from kernel sources", color = ColorChoice::Always)]
struct Args {
    /// Path to the kernel source directory
    #[arg(short, long)]
    kernel_dir: String,

    /// Path to the vmlinux.h file to annotate
    #[arg(short, long)]
    vmlinux_h: String,

    /// Path to the output file (default: vmlinux_annotated.h)
    #[arg(short, long, default_value = "vmlinux_annotated.h")]
    output: String,
}

/// Builds a map of BPF kfunc signatures to their comments from kernel source files
fn build_bpf_kfunc_map(kernel_dir: &str) -> HashMap<String, String> {
    // Get all .c and .h files
    let files: Vec<_> = walkdir::WalkDir::new(kernel_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.is_file() && path.extension().is_some_and(|ext| ext == "c" || ext == "h")
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    println!("Found {} files to process", files.len());

    // Process files sequentially
    let mut comments_map = HashMap::new();

    for file in files {
        let content = match fs::read_to_string(&file) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Error reading {}: {}", file.display(), e);
                continue;
            }
        };

        let mut current_comment = String::new();
        let mut in_comment = false;
        let mut prev_was_close = false;
        let mut last_comment_line = 0;
        let mut line_number = 0;

        for line in content.lines() {
            line_number += 1;

            if line.contains("/**") {
                in_comment = true;
                current_comment.clear();
                current_comment.push_str(line);
                current_comment.push('\n');
            } else if in_comment {
                if line.contains("*/") {
                    current_comment.push_str(line);
                    in_comment = false;
                    prev_was_close = true;
                    last_comment_line = line_number;
                } else {
                    current_comment.push_str(line);
                    current_comment.push('\n');
                }
            } else if !current_comment.is_empty() && line.contains("__bpf_kfunc") {
                if line.contains("(") && line.contains(" ") {
                    let sig = (" ".to_owned()
                        + line
                            .trim()
                            .to_string()
                            .split_terminator('(')
                            .collect::<Vec<&str>>()[0]
                            .split_terminator(' ')
                            .collect::<Vec<&str>>()
                            .last()
                            .unwrap()
                            .to_string()
                            .to_owned()
                            .as_str()
                        + "(")
                        .to_string();
                    comments_map.insert(sig, current_comment.trim().to_string());
                }
                current_comment.clear();
                prev_was_close = false;
            } else if !line.is_empty()
                && prev_was_close
                && (line_number - last_comment_line > 1 || line.contains("__bpf_kptr"))
            {
                // Only clear the comment if we're far from the last comment or if we encounter __bpf_kptr
                current_comment.clear();
                prev_was_close = false;
            }
        }
    }

    println!("Processing complete");
    comments_map
}

/// Adds comments to vmlinux.h based on the provided comments map
fn annotate_vmlinux(
    vmlinux_h: &str,
    comments_map: &HashMap<String, String>,
    struct_map: &HashMap<String, String>,
) -> Result<String, std::io::Error> {
    // Read vmlinux.h
    let content = fs::read_to_string(vmlinux_h)?;

    // Process the file and add comments
    let mut output = String::new();
    let mut matches_found = 0;
    let mut struct_matches_found = 0;

    for line in content.lines() {
        // Check if this line contains a function that matches one of our keys
        for (key, comment) in comments_map {
            if line.contains("extern") && line.contains(key) {
                output.push_str(comment);
                output.push('\n');
                matches_found += 1;
                break;
            }
        }

        // Check if this line contains a struct or enum that matches one of our keys
        for (key, comment) in struct_map {
            if line.contains(key) && (line.contains("struct") || line.contains("enum")) {
                output.push_str(comment);
                output.push('\n');
                struct_matches_found += 1;
                break;
            }
        }

        output.push_str(line);
        output.push('\n');
    }

    println!(
        "Added {matches_found} function comments and {struct_matches_found} struct/enum comments to vmlinux.h"
    );
    Ok(output)
}

fn build_kernel_struct_map(kernel_dir: &str) -> HashMap<String, String> {
    // Get all .c and .h files
    let files: Vec<_> = walkdir::WalkDir::new(kernel_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.is_file() && path.extension().is_some_and(|ext| ext == "c" || ext == "h")
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    println!("Found {} files to process", files.len());

    // Process files sequentially
    let mut struct_map = HashMap::new();

    for file in files {
        let content = match fs::read_to_string(&file) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Error reading {}: {}", file.display(), e);
                continue;
            }
        };

        let mut current_comment = String::new();
        let mut in_comment = false;
        let mut last_comment_line = 0;
        let mut line_number = 0;

        for line in content.lines() {
            line_number += 1;

            if line.contains("/**") {
                in_comment = true;
                current_comment.clear();
                current_comment.push_str(line);
                current_comment.push('\n');
            } else if in_comment {
                if line.contains("*/") {
                    current_comment.push_str(line);
                    in_comment = false;
                    last_comment_line = line_number;
                } else {
                    current_comment.push_str(line);
                    current_comment.push('\n');
                }
            } else if !current_comment.is_empty()
                && (line.trim().starts_with("struct") || line.trim().starts_with("enum"))
                && line.trim().ends_with(" {")
                && line
                    .trim()
                    .split_terminator(' ')
                    .collect::<Vec<&str>>()
                    .len()
                    == 3
                && (line_number - last_comment_line <= 1)
            {
                let mut key =
                    line.trim().split_terminator(' ').collect::<Vec<&str>>()[1].to_string();
                if line.contains("struct") {
                    key = "struct ".to_string() + key.as_str() + " {";
                } else if line.contains("enum") {
                    key = "enum ".to_string() + key.as_str() + " {";
                }
                struct_map.insert(key.clone(), current_comment.clone());
                current_comment.clear();
            } else if !line.is_empty()
                && !current_comment.is_empty()
                && (line_number - last_comment_line > 1)
            {
                // Only clear the comment if we're far from the last comment
                current_comment.clear();
            }
        }
    }

    println!("Processing complete");
    struct_map
}

fn main() {
    let args = Args::parse();

    // Build the map of __bpf_kfunc declarations to their comments
    let comments_map = build_bpf_kfunc_map(&args.kernel_dir);
    println!(
        "Found {} __bpf_kfunc declarations with comments",
        comments_map.len()
    );

    // Build the map of structs and enums to their comments and definitions
    let struct_map = build_kernel_struct_map(&args.kernel_dir);
    println!("Found {} structs and enums with comments", struct_map.len());

    // Annotate vmlinux.h with comments
    match annotate_vmlinux(&args.vmlinux_h, &comments_map, &struct_map) {
        Ok(annotated_content) => {
            // Write the annotated output
            if let Err(e) = fs::write(&args.output, annotated_content) {
                eprintln!("Error writing annotated file: {e}");
                process::exit(1);
            }
            println!("Successfully wrote annotated vmlinux.h to {}", args.output);
        }
        Err(e) => {
            eprintln!("Error processing vmlinux.h: {e}");
            process::exit(1);
        }
    }
}
