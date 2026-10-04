//! Named pause points that stop production code at an exact step while a test holds them.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use crate::sealed::{SealError, unpoison};

/// Bound on every wait between a paused thread and its test.
///
/// Paused steps release within milliseconds, so a few seconds also bounds a test that blocks on
/// a lock its own paused thread holds.
pub(crate) const BOUND: Duration = Duration::from_secs(5);

enum Answer {
    Resume,
    Fail(SealError),
    Panic,
}

/// One thread stopped at an armed point, released exactly once and resumed if dropped.
pub(crate) struct Arrival {
    pub(crate) thread: Option<String>,
    release: Option<Sender<Answer>>,
}

impl Arrival {
    pub(crate) fn resume(mut self) {
        self.answer(Answer::Resume);
    }

    /// Makes the paused call return `error` at this point.
    pub(crate) fn fail(mut self, error: SealError) {
        self.answer(Answer::Fail(error));
    }

    /// Unwinds the paused thread, standing in for a process that stops at this point.
    pub(crate) fn panic(mut self) {
        self.answer(Answer::Panic);
    }

    fn answer(&mut self, answer: Answer) {
        if let Some(release) = self.release.take() {
            // A paused thread that already gave up has nothing left to release.
            let _ = release.send(answer);
        }
    }
}

impl Drop for Arrival {
    fn drop(&mut self) {
        self.answer(Answer::Resume);
    }
}

type Key = (String, &'static str);

static POINTS: LazyLock<Mutex<HashMap<Key, Sender<Arrival>>>> = LazyLock::new(Mutex::default);

/// The arrivals at one armed point, which is disarmed when this is dropped.
pub(crate) struct Arrivals {
    key: Key,
    receiver: Receiver<Arrival>,
}

impl Arrivals {
    /// The next thread to reach the point, panicking if none does within [`BOUND`].
    pub(crate) fn next(&self) -> Arrival {
        self.receiver
            .recv_timeout(BOUND)
            .unwrap_or_else(|_| panic!("no thread reached pause point {}", self.key.1))
    }

    /// The next arrival within `bound`, or `None` once it passes.
    pub(crate) fn within(&self, bound: Duration) -> Option<Arrival> {
        match self.receiver.recv_timeout(bound) {
            Ok(arrival) => Some(arrival),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => unreachable!("the registry keeps the sender"),
        }
    }
}

impl Drop for Arrivals {
    fn drop(&mut self) {
        unpoison(POINTS.lock()).remove(&self.key);
    }
}

/// Arms `point` for the store whose targets start with `prefix`.
pub(crate) fn arm(prefix: &str, point: &'static str) -> Arrivals {
    let key = (prefix.to_owned(), point);
    let (sender, receiver) = mpsc::channel();
    let previous = unpoison(POINTS.lock()).insert(key.clone(), sender);
    assert!(previous.is_none(), "pause point {point} armed twice");
    Arrivals { key, receiver }
}

/// Stops the calling thread here while a test holds `point` armed for `prefix`.
pub(crate) fn reached(prefix: &str, point: &'static str) -> Result<(), SealError> {
    let Some(sender) = unpoison(POINTS.lock())
        .get(&(prefix.to_owned(), point))
        .cloned()
    else {
        return Ok(());
    };
    let (release, answer) = mpsc::channel();
    let arrival = Arrival {
        thread: std::thread::current().name().map(str::to_owned),
        release: Some(release),
    };
    if sender.send(arrival).is_err() {
        return Ok(());
    }
    match answer.recv_timeout(BOUND) {
        Ok(Answer::Resume) | Err(RecvTimeoutError::Disconnected) => Ok(()),
        Ok(Answer::Fail(error)) => Err(error),
        Ok(Answer::Panic) => panic!("stopped at pause point {point}"),
        Err(RecvTimeoutError::Timeout) => panic!("pause point {point} was never answered"),
    }
}
