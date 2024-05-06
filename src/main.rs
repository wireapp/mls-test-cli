mod backend;
mod client;
mod commands;
mod credential;
mod keystore;

use futures::executor::block_on;

fn main() {
    block_on(commands::run());
}
