use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match sbm_server::Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("sbm-server: {err}");
            return ExitCode::from(2);
        }
    };
    let json = config.log_json;
    init_tracing(json);
    let server = match sbm_server::serve(config).await {
        Ok(server) => server,
        Err(err) => {
            tracing::error!(error = %err, "startup failed");
            eprintln!("sbm-server: {err}");
            return ExitCode::from(1);
        }
    };
    tracing::info!(url = %server.base_url, "listening");
    println!("sbm-server listening on {}", server.base_url);
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::warn!("ctrl-c listener closed");
    }
    drop(server);
    ExitCode::SUCCESS
}

fn init_tracing(json: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn,h2=warn"));
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
}
