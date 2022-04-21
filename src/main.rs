use std::net::TcpStream;

use clap::Parser as _;
use anyhow::{Result, Context, ensure};

use gdb_protocol::packet::{CheckedPacket, Kind};
use gdb_protocol::parser::Parser;

use std::io::prelude::*;

struct Gdb {
    conn: TcpStream,
    buf: Vec<u8>,
    buf_len: usize,
    parser: Parser,
}

impl Gdb {
    pub fn new(remote_addr: &str) -> Result<Self> {
        let conn = TcpStream::connect(remote_addr)
            .with_context(|| format!("Failed to connect to {}", remote_addr))?;
        let mut buf = vec![];
        buf.resize(1024*10, 0);
        let parser = Default::default();
        let buf_len = 0;
        Ok(Self { conn, buf, buf_len, parser })
    }

    pub fn recv_next_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let bytes_read = self.conn.read(&mut self.buf[self.buf_len..])
                .context("Failed to receive gdb packet")?;
            self.buf_len += bytes_read;
            let (consumed, packet) = self.parser.feed(&mut self.buf[0..self.buf_len])
                .context("Failed to parse gdb packet")?;

            assert!(consumed <= self.buf_len);
            if consumed > 0 && consumed != self.buf_len {
                self.buf.copy_within(consumed..self.buf_len, 0);
            }
            self.buf_len -= consumed;

            if let Some(packet) = packet {
                ensure!(packet.is_valid(), "Received gdb packet is invalid");
                return Ok(packet.data)
            }
        }
    }

    pub fn send_packet(&mut self, data: Vec<u8>) -> Result<()> {
        CheckedPacket::from_data(Kind::Packet, data).encode(&mut self.conn)
            .context("Failed to send gdb packet")?;
        Ok(())
    }

    pub fn send(&mut self, cmd: String) -> Result<()> {
        self.send_packet(cmd.into_bytes())?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<String> {
        let data = self.recv_next_packet()?;
        self.send("+".to_string())?;
        let data = String::from_utf8(data)
            .context("Data is invalid UTF8")?;
        Ok(data)
    }

    pub fn read_mem(&mut self, addr: u64, dst: &mut [u8]) -> Result<()> {
        self.send(format!("m{:x},{}", addr, dst.len()))?;
        let recv = self.recv()?;
        hex::decode_to_slice(recv, dst)
            .context("Data is invalid hex")?;
        Ok(())
    }

    pub fn write_mem(&mut self, addr: u64, dst: &[u8]) -> Result<()> {
        self.send(format!("M{:x},{}:{}", addr, dst.len(), hex::encode(dst)))?;
        let recv = self.recv()?;
        ensure!(recv == "OK");
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        self.send("c".to_string())?;
        Ok(())
    }

    pub fn read_reg(&mut self, addr: u64) -> Result<u32> {
        let mut data = [0; 4];
        self.read_mem(addr, &mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    pub fn write_reg(&mut self, addr: u64, value: u32) -> Result<()> {
        let data = u32::to_le_bytes(value);
        self.write_mem(addr, &data)?;
        Ok(())
    }
}

const IDR_OFFSET: u64 = 0x10;
const ODR_OFFSET: u64 = 0x14;


// f(port, values)
fn iter_port_reg_changes(old_value: u32, new_value: u32, stride: u8, mut f: impl FnMut(u8, u8)) {
    let mut changes = old_value ^ new_value;
    let stride_mask = 0xFF >> (8 - stride);
    while changes != 0 {
        let right_most_bit = changes.trailing_zeros() as u8;
        let port = right_most_bit / stride;
        if port <= 16 {
            let v = (new_value >> (port*stride)) as u8 & stride_mask;
            f(port, v);
        }
        changes &= !(stride_mask as u32) << (port*stride);
    }
}

#[derive(Default)]
struct Port {
    pub letter: char,
    addr: u32,

    idr: u32,
    odr: u32,

    mask_ignore: u16,

    watch_input: bool,
    watch_output: bool,
}

impl Port {
    pub fn new(letter: char, addr: u32) -> Self {
        Self { letter, addr, ..Default::default() }
    }

    pub fn port_prefix(&self) -> String {
        format!("P{}", self.letter)
    }

    fn pin_ignore(&self, pin: u8) -> bool {
        self.mask_ignore & (1 << pin) != 0
    }

    pub fn refresh(&mut self, gdb: &mut Gdb) -> Result<()> {
        if self.watch_input {
            let new_idr = gdb.read_reg(self.addr as u64 + IDR_OFFSET)?;
            iter_port_reg_changes(self.idr, new_idr, 1, |pin, v| {
                if !self.pin_ignore(pin) {
                    println!("P{}{} input={}", self.letter, pin, v);
                }
            });
            self.idr = new_idr;
        }

        if self.watch_output {
            let new_odr = gdb.read_reg(self.addr as u64 + ODR_OFFSET)?;
            iter_port_reg_changes(self.odr, new_odr, 1, |pin, v| {
                if !self.pin_ignore(pin) {
                    println!("P{}{} output={}", self.letter, pin, v);
                }
            });
            self.odr = new_odr;
        }

        Ok(())
    }
}

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of GDB server (e.g., localhost:2331)
    #[clap(short, long)]
    remote: String,

    /// Ports, or pins to ignore
    #[clap(short, long="ignore", value_delimiter=',')]
    ignores: Vec<String>,

    /// Watch input, or output, (default is both).
    #[clap(short, long="watch", value_delimiter=',', arg_enum)]
    watches: Vec<WatchKind>,
}

#[derive(clap::ArgEnum, Clone, Debug)]
enum WatchKind {
    Input,
    Output,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut gdb = Gdb::new(&args.remote)?;

    // Slow everything down by adding a prescaler to hclk
    //gdb.write_reg(0x40023808, 0x0000940A | (0b1111 << 4))?;
    gdb.write_reg(0x40023808, 0x0000940A | (0b1011 << 4))?;

    gdb.resume()?;

    let ports = vec![
        Port::new('A', 0x40020000),
        Port::new('B', 0x40020400),
        Port::new('C', 0x40020800),
        Port::new('D', 0x40020c00),
        Port::new('E', 0x40021000),
        Port::new('F', 0x40021400),
        Port::new('G', 0x40021800),
    ];

    let mut ports = ports.into_iter()
        .filter(|p| !args.ignores.contains(&p.letter.to_string()))
        .collect::<Vec<_>>();

    for port in &mut ports {
        let port_prefix = port.port_prefix();
        for ignore in &args.ignores {
            if let Some(pin) = ignore.strip_prefix(&port_prefix) {
                let pin = pin.parse::<usize>().context("port ignore integer parse error")?;
                port.mask_ignore |= 1 << pin;
            }
        }

        if args.watches.is_empty() {
            port.watch_input = true;
            port.watch_output = true;
        } else {
            for w in &args.watches {
                match w {
                    WatchKind::Input => port.watch_input = true,
                    WatchKind::Output => port.watch_output = true,
                }
            }
        }
    }

    loop {
        for port in &mut ports {
            port.refresh(&mut gdb)?;
        }
    }
}
