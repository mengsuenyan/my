pub mod cmd;
pub mod encode;
pub mod error;
pub mod fs;
pub mod ty;

fn log_error<T>(x: Result<T, anyhow::Error>) -> Option<T> {
    x.map_err(|e| {
        log::error!("{e}");
    })
    .ok()
}
