use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::thread::{sleep, spawn};
use std::time::Duration;

#[derive(Default)]
pub struct PipeDataCmd {
    s: Cell<String>,
    sleep: usize,
}

impl PipeDataCmd {
    pub fn new(sleep: usize) -> Self {
        Self {
            s: Cell::new(String::new()),
            sleep,
        }
    }

    pub fn pipe_data(&self) -> String {
        let s = self.s.take();
        self.s.set(s.clone());
        s
    }

    fn read_stdin() -> Receiver<String> {
        let (s, r) = channel();

        spawn(move || {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                log::error!("read pipe data failed, due to: {}", e);
            }

            if let Err(e) = s.send(buf) {
                log::error!("Send pipe data failed, due to: {}", e);
            }
        });

        r
    }
}

impl Display for PipeDataCmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.pipe_data().as_str())
    }
}

impl Clone for PipeDataCmd {
    fn clone(&self) -> Self {
        let s = self.pipe_data();

        Self {
            s: Cell::new(s),
            sleep: self.sleep,
        }
    }
}

impl Cmd for PipeDataCmd {
    const NAME: &'static str = "pipe";

    fn cmd() -> Command {
        Command::new(Self::NAME).about("get pipe data").arg(
            Arg::new("sleep")
                .value_name("ms")
                .long("sleep")
                .short('s')
                .action(ArgAction::Set)
                .required(false)
                .default_value("1")
                .value_parser(value_parser!(usize))
                .help("sleep duration before try to receive data"),
        )
    }

    fn run(&self, m: &ArgMatches) {
        let rev = Self::read_stdin();
        let dur = m
            .get_one::<usize>("sleep")
            .copied()
            .unwrap_or(1)
            .max(self.sleep) as u64;

        sleep(Duration::from_millis(dur));
        match rev.try_recv() {
            Ok(x) => {
                self.s.set(x);
            }
            Err(e) => {
                if e != TryRecvError::Empty {
                    log::error!("{e}");
                }
            }
        }
    }
}
