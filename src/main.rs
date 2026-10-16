mod backend;
mod client;
mod commands;
mod credential;
mod keystore;
mod targeted;
mod transient;

use futures::executor::block_on;

fn main() {
    block_on(commands::run());
}
