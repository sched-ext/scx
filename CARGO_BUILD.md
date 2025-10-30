# Building schedulers in the `scx` project

The `scx` repository is organized as a **Cargo workspace** containing multiple schedulers, shared libraries, and tools.
Schedulers are implemented as individual Rust crates under `scheds/rust/*`.

This document explains how to build the entire project as well as individual schedulers and tools.

---

## 1. Available build profiles

The project defines several Cargo build profiles in the top-level `Cargo.toml`:

- **release**
  Thin LTO enabled (default for production).

- **release-tiny**
  Stripped, thin LTO, optimized for small binary size.

- **release-fast**
  Optimized for compilation speed and native CPU optimizations, no LTO.

You can select a profile using the `--profile` option, for example:

```bash
cargo build --profile=release-tiny
```

---

## 2. Building the entire workspace

To build **all crates** (schedulers, libraries, and tools):

- Debug build (default):

  ```bash
  cargo build
  ```

- Optimized release build:

  ```bash
  cargo build --release
  ```

- Tiny profile:

  ```bash
  cargo build --profile=release-tiny
  ```

- Fast profile:

  ```bash
  cargo build --profile=release-fast
  ```

---

## 3. Building individual schedulers

Each scheduler is its own Cargo package. You can build a single one using:

```bash
cargo build --profile=<profile> -p <scheduler_name>
```

Example for **scx_flash** with **release-tiny**:

```bash
cargo build --profile=release-tiny -p scx_flash
```

---

### List of schedulers

| Scheduler name | Example build command |
|----------------|------------------------|
| `scx_bpfland`  | `cargo build --release -p scx_bpfland` |
| `scx_chaos`    | `cargo build --release -p scx_chaos` |
| `scx_cosmos`   | `cargo build --release -p scx_cosmos` |
| `scx_flash`    | `cargo build --release -p scx_flash` |
| `scx_lavd`     | `cargo build --release -p scx_lavd` |
| `scx_layered`  | `cargo build --release -p scx_layered` |
| `scx_mitosis`  | `cargo build --release -p scx_mitosis` |
| `scx_p2dq`     | `cargo build --release -p scx_p2dq` |
| `scx_rlfifo`   | `cargo build --release -p scx_rlfifo` |
| `scx_rustland` | `cargo build --release -p scx_rustland` |
| `scx_rusty`    | `cargo build --release -p scx_rusty` |
| `scx_tickless` | `cargo build --release -p scx_tickless` |
| `scx_wd40`     | `cargo build --release -p scx_wd40` |

---

## 4. Building tools

Besides schedulers, the workspace includes several tools:

- **scxtop** – Monitoring tool:

  ```bash
  cargo build --release -p scxtop
  ```

- **scxcash** – Caching utility:

  ```bash
  cargo build --release -p scxcash
  ```

- **vmlinux_docify** – Kernel documentation generator:

  ```bash
  cargo build --release -p vmlinux_docify
  ```

---

## 5. Installing from crates.io

Some schedulers and tools may also be available directly from [crates.io](https://crates.io). This allows you to install them without cloning the repository.

### Examples

| Crate name   | Install command            |
|--------------|----------------------------|
| `scxtop`     | `cargo install scxtop`     |
| `scx_flash`  | `cargo install scx_flash`  |

This will place the binary in `~/.cargo/bin`, which you should add to your `PATH` if it is not already included.

> **Note**: Availability on crates.io depends on which components the maintainers publish there. Not all schedulers may be published.

### Installing system-wide

To make a scheduler or tool available system-wide, you can either:

1. Copy the installed binary from `~/.cargo/bin` into a system directory, e.g.:

   ```bash
   sudo cp ~/.cargo/bin/scxtop /usr/local/bin/
   ```

2. Or add `~/.cargo/bin` to your system `PATH`, for example by adding this line to `~/.bashrc` or `~/.zshrc`:

   ```bash
   export PATH="$HOME/.cargo/bin:$PATH"
   ```

---

## 6. Running tests

To verify the correctness of the build, you can run tests:

- For the entire workspace:

  ```bash
  cargo test
  ```

- For a specific scheduler:

  ```bash
  cargo test -p scx_flash
  ```

---

## 7. Dependency management

The workspace uses a shared `Cargo.lock` file.

- To prefetch dependencies for offline builds:

  ```bash
  cargo fetch --locked
  ```

- To update dependencies:

  ```bash
  cargo update
  ```

---

## 8. Cross-compilation

You can build for different targets, for example **musl**:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Make sure the target is installed first:

```bash
rustup target add x86_64-unknown-linux-musl
```

---

## 9. Debugging

- Enable backtraces:

  ```bash
  sudo env RUST_BACKTRACE=1 ./target/debug/scx_flash
  ```

- Enable debug logging:

  ```bash
  sudo env RUST_LOG=debug ./target/debug/scx_flash
  ```

---

## 10. Cleaning up

To remove build artifacts and start fresh:

```bash
cargo clean
```

---

## 11. Summary

- **Build everything**: `cargo build --release`
- **Build one scheduler**: `cargo build --profile=<profile> -p <name>`
- **Install from crates.io**: `cargo install <crate_name>`
- **Make available system-wide**: copy binary to `/usr/local/bin` or add `~/.cargo/bin` to `PATH`
- **Run tests**: `cargo test`
- **Cross-compile**: `cargo build --target=<target>`
- **Profiles available**: `release`, `release-tiny`, `release-fast`

This approach allows you to build and test either the whole project at once or focus on a single scheduler or tool.
