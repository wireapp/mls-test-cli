mod backend;
mod client;
mod commands;
mod credential;
mod keystore;

use futures_lite::future;

fn main() {
    future::block_on(commands::run());
}
