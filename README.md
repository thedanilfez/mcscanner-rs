# mcscanner-rs
Minecraft server scanner written in rust

## Build
```bash
git clone https://github.com/thedanilfez/mcscanner-rs.git
cd mscanner-rs
cargo build --release
# ./target/release/mcscanner-rs
```

## Usage
```bash
./mcscanner-rs [OPTIONS]
```
+ `-c --concurrency <N>` - Maximum number of concurrent connections
+ `-d --debug` - Enable debug logging
+ `-i --input <FILE>` - Path to the input file
+ `-o --output <FILE>` - Path to the output file
+ `-p --port <PORT>` - Port to scan

## License
This project is licensed under the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)