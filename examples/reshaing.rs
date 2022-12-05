use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use std::vec;
use structopt::StructOpt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;

mod gg20_sm_client;
use gg20_sm_client::join_computation;
mod common;
use opentelemetry::global;
use opentelemetry::sdk::trace as sdktrace;
use opentelemetry::trace::{FutureExt, TraceError};
use opentelemetry::Key;
use opentelemetry::{
    trace::{TraceContextExt, Tracer},
    Context as o_ctx,
};

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long)]
    output: PathBuf,

    #[structopt(short, long)]
    index: u16,
    #[structopt(short, long)]
    threshold: u16,
    #[structopt(short, long)]
    number_of_parties: u16,
    #[structopt(short, long)]
    role: u8,
}

fn init_tracer() -> Result<sdktrace::Tracer, TraceError> {
    opentelemetry_jaeger::new_agent_pipeline()
        // .with_endpoint("66.42.55.28:6831")
        .with_auto_split_batch(true) // Auto split batches so they fit under packet size
        .with_service_name("key-reshaing")
        .install_batch(opentelemetry::runtime::Tokio)
}

#[tokio::main]
async fn main() -> Result<()> {
    let tracer = init_tracer()?;

    let span = tracer.start("root");
    let cx = o_ctx::current_with_span(span);

    let args: Cli = Cli::from_args();
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let s_span = cx.span();

    s_span.add_event("keygen staring".to_string(), vec![]);

    s_span.add_event(
        "cli-properties".to_string(),
        vec![
            Key::new("index").i64(args.index as i64),
            Key::new("threshold").i64(args.threshold as i64),
            Key::new("number_of_parties").i64(args.number_of_parties as i64),
        ],
    );

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;

    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .with_context(cx.clone())
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;

    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .with_context(cx)
        .await
        .context("save output to file")?;

    global::shutdown_tracer_provider();
    Ok(())
}
