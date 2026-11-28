//! Run a disposable deploy-proof target fixture.
//!
//! Usage: membrane-proof-target [--listen 127.0.0.1:9301] [--state-file PATH]

fn main() {
    let mut listen = "127.0.0.1:9301".to_string();
    let mut state_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args.next().unwrap_or_else(|| {
                    eprintln!("--listen needs a value");
                    std::process::exit(2);
                });
            }
            "--state-file" => {
                state_file = Some(std::path::PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--state-file needs a value");
                    std::process::exit(2);
                })));
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        println!("proof target on {listen} (state_file={state_file:?})");
        if let Err(e) = membrane_proof_target::serve(&listen, state_file).await {
            eprintln!("target failed: {e}");
            std::process::exit(1);
        }
    });
}
