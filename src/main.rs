use crate::scanner::scan;
use clap::Parser;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tracing::{error, info};

mod packets;
mod protocol;
mod scanner;

type ScanResult = (String, i64, i64, String, bool);

#[derive(Parser, Debug)]
#[command(author, version, about = "mcscanner-rs")]
struct Args {
    #[arg(short, long, default_value_t = 300)]
    concurrency: usize,
    #[arg(short, long, default_value = "input.txt")]
    input: String,
    #[arg(short, long, default_value = "output.txt")]
    output: String,
    #[arg(short, long, default_value_t = 25565)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter("mcscanner=info")
        .init();

    info!("mcscanner-rs");

    let input = tokio::fs::read_to_string(&args.input).await.map_err(|e| {
        error!("Error while reading {}: {}", args.input, e);
        std::process::exit(1);
    })?;

    let ranges: Vec<String> = input.lines().map(|s| s.to_string()).collect();

    info!("got {} targets!", ranges.len());

    let start = Instant::now();
    let limit = Arc::new(Semaphore::new(args.concurrency));
    let mut set = JoinSet::<Option<ScanResult>>::new();

    let (tx, mut rx) = mpsc::channel::<String>(100);

    let writer = tokio::spawn(async move {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(args.output)
            .await
            .expect("failed to open file");

        while let Some(msg) = rx.recv().await {
            let _ = file.write_all(msg.as_bytes()).await;
        }
    });

    for range_str in &ranges {
        let net: Ipv4Net = range_str
            .parse()
            .or_else(|_| range_str.parse::<Ipv4Addr>().map(Ipv4Net::from))
            .expect("Invalid IP");
        for ip in net.hosts() {
            let target = format!("{}:{}", ip, args.port);
            let permit = limit.clone().acquire_owned().await.unwrap();

            let target_clone = target.clone();
            set.spawn(async move {
                let _permit = permit;
                let res = tokio::time::timeout(
                    Duration::from_millis(4000),
                    scan(&target_clone, args.port),
                )
                .await;

                match res {
                    Ok(Ok((players, max, motd, is_whitelisted))) => {
                        Some((target_clone, players, max, motd, is_whitelisted))
                    }
                    _ => None,
                }
            });

            while let Some(res) = set.try_join_next() {
                let _ = handle(res, tx.clone()).await;
            }
        }
    }

    while let Some(res) = set.join_next().await {
        handle(res, tx.clone()).await?;
    }

    let duration = start.elapsed();

    info!("Scan OK in {:.1}s.", duration.as_secs_f32());

    drop(tx);
    let _ = writer.await;

    Ok(())
}

async fn handle(
    res: Result<Option<ScanResult>, tokio::task::JoinError>,
    tx: mpsc::Sender<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(Some((addr, players, max, motd, is_whitelisted))) = res {
        // filter 0 max players (broken) and big servers
        if max > 0 && players < 100 && !is_whitelisted {
            info!("Found {} ({} / {}) - {}", addr, players, max, motd);
            let _ = tx
                .send(format!("{} ({} / {}) - {}\n", addr, players, max, motd))
                .await;
        }
    }
    Ok(())
}
