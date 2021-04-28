mod error;
mod probe;
mod config;

pub use error::*;

use config::Config;
use getopts::Options;
use log::{debug, error};
use futures::future::{BoxFuture, join_all};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} CONFIG [options]", program);
    print!("{}", opts.usage(&brief));
}

#[async_std::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Display this help text and exit");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f)
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let cfg_path = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    env_logger::init();

    let cfg = Config::from_path(&cfg_path).await.unwrap_or_else(|e| {
        error!("parsing config failed: {}", e.to_string());
        std::process::exit(1);
    });

    debug!("\n{:#?}", cfg);

    let tasks: Vec<BoxFuture<Result<()>>> = vec![
        Box::pin(probe::send(cfg.clone())),
        Box::pin(probe::recv(cfg.clone())),
    ];
    join_all(tasks).await.into_iter().collect::<Result<()>>().unwrap_or_else(|e| {
        error!("{}", e.to_string());
        std::process::exit(1);
    });
}
