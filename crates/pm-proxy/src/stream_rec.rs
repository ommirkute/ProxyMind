//! Recording of raw TCP and TLS streams (roadmap 2.6).
//!
//! A [`StreamTap`] sits beside the relay: the relay passes every chunk it moved to it, after writing it to the other
//! side. The tap never touches the bytes on their way; it counts them and, while the recording caps allow, sends a
//! copy to the recorder's writer thread. Bytes past a cap are relayed and counted only, and the stream is marked
//! truncated.

use parking_lot::Mutex;
use pm_core::now_ms;
use pm_store::{NewChunk, NewExchange, NewStream, STREAM_CHUNK_CAP, STREAM_RECORD_CAP, StreamEnd, StreamOp};

use crate::{Record, Recorder};

#[derive(Default)]
struct State {
    to_server: u64,
    to_client: u64,
    /// Bytes and chunks stored so far.
    kept: u64,
    chunks: u64,
    truncated: bool,
    finished: bool,
}

/// Counts a stream's bytes and records them when the recording settings allow it.
pub(crate) struct StreamTap {
    rec: Option<(Recorder, u64)>,
    state: Mutex<State>,
}

impl Recorder {
    /// Whether a stream to this target from this client is recorded: the same settings as for exchanges (in scope
    /// only, chosen devices), asked with the stream's scope target (`https` for TLS, else `http`, path `/`).
    fn keep_stream(&self, s: &NewStream) -> bool {
        let probe = NewExchange {
            scheme: if s.tls { "https" } else { "http" }.into(),
            host: s.host.clone(),
            port: s.port,
            path: "/".into(),
            client_addr: s.client_addr.clone(),
            ..Default::default()
        };
        self.keep(&probe)
    }
}

impl StreamTap {
    /// Opens a stream: its row is written when the settings keep it. Without a recording (`record` false, or the
    /// settings drop it) the tap only counts.
    pub(crate) fn open(recorder: &Recorder, record: bool, s: NewStream) -> Self {
        let rec = (record && recorder.keep_stream(&s)).then(|| {
            let key = recorder.next_key.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            recorder.send(Record::Stream(StreamOp::Open(key, s)));
            (recorder.clone(), key)
        });
        Self { rec, state: Mutex::new(State::default()) }
    }

    /// One chunk that crossed the proxy, in the direction `to_server`.
    pub(crate) fn chunk(&self, to_server: bool, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut st = self.state.lock();
        if to_server {
            st.to_server += data.len() as u64;
        } else {
            st.to_client += data.len() as u64;
        }
        let Some((rec, key)) = &self.rec else { return };
        if st.chunks >= STREAM_CHUNK_CAP || st.kept >= STREAM_RECORD_CAP {
            st.truncated = true;
            return;
        }
        let room = usize::try_from(STREAM_RECORD_CAP - st.kept).unwrap_or(usize::MAX);
        let take = data.len().min(room);
        if take < data.len() {
            st.truncated = true;
        }
        st.kept += take as u64;
        st.chunks += 1;
        let chunk = NewChunk { ts_ms: now_ms(), to_server, len: data.len() as u64, data: data[..take].to_vec() };
        // Sent under the lock so chunks of the two directions reach the writer in the order they were moved.
        rec.send(Record::Stream(StreamOp::Chunk(*key, chunk)));
    }

    /// Bytes moved towards the server and towards the client so far.
    pub(crate) fn totals(&self) -> (u64, u64) {
        let st = self.state.lock();
        (st.to_server, st.to_client)
    }

    /// Ends the stream (once): `ended` says how, `error` why when it was an error.
    pub(crate) fn finish(&self, ended: &str, error: Option<String>) {
        let mut st = self.state.lock();
        if std::mem::replace(&mut st.finished, true) {
            return;
        }
        if let Some((rec, key)) = &self.rec {
            let end = StreamEnd {
                end_ms: now_ms(),
                bytes_to_server: st.to_server,
                bytes_to_client: st.to_client,
                truncated: st.truncated,
                ended: ended.to_string(),
                error,
            };
            rec.send(Record::Stream(StreamOp::End(*key, end)));
        }
    }
}

impl Drop for StreamTap {
    /// A relay that was dropped (its task cancelled) still closes the row.
    fn drop(&mut self) {
        self.finish("error", Some("the relay was stopped".into()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pm_store::Store;

    use super::*;

    fn stream() -> NewStream {
        NewStream { start_ms: 1, host: "h.test".into(), port: 9, source: "proxy".into(), ..Default::default() }
    }

    fn wait_written(r: &Recorder, n: u64) {
        for _ in 0..200 {
            if r.written_records() >= n {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the writer did not handle {n} records");
    }

    #[test]
    fn chunks_are_kept_up_to_the_cap_then_only_counted() {
        let dir = std::env::temp_dir().join(format!("pm-tap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.pmproj");
        let (rec, _w) = Recorder::spawn(Store::open(&path).unwrap());
        let tap = StreamTap::open(&rec, true, stream());
        let block = vec![7u8; 1 << 20];
        // 17 MiB toward the server: 16 are kept, the 17th is dropped (the cap fell on a chunk boundary).
        for _ in 0..17 {
            tap.chunk(true, &block);
        }
        tap.chunk(false, b"late answer");
        tap.finish("server_closed", None);
        tap.finish("error", None); // a second finish does nothing
        assert_eq!(tap.totals(), (17 << 20, 11));
        wait_written(&rec, 1 + 16 + 1);
        let s = Store::open(&path).unwrap();
        let row = s.get_stream(1).unwrap().unwrap();
        assert!(row.truncated);
        assert_eq!((row.bytes_to_server, row.bytes_to_client, row.chunks), (17 << 20, 11, 16));
        assert_eq!(row.ended.as_deref(), Some("server_closed"));
        assert_eq!(s.stream_chunks(1, None, 100, None).unwrap().len(), 16);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_chunk_over_the_cap_is_cut_and_keeps_its_wire_length() {
        let (rec, _w) = Recorder::spawn(Store::open_in_memory().unwrap());
        let tap = StreamTap::open(&rec, true, stream());
        tap.chunk(true, &vec![1u8; (STREAM_RECORD_CAP - 4) as usize]);
        tap.chunk(true, &[9u8; 10]);
        let st = tap.state.lock();
        assert_eq!((st.kept, st.chunks, st.truncated), (STREAM_RECORD_CAP, 2, true));
    }

    #[test]
    fn the_filter_decides_whether_a_stream_is_recorded() {
        let (rec, _w) = Recorder::spawn(Store::open_in_memory().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        rec.set_filter(Some(Arc::new(move |ex| {
            log.lock().push((ex.scheme.clone(), ex.host.clone(), ex.port, ex.client_addr.clone()));
            ex.host == "yes.test"
        })));
        let yes = StreamTap::open(&rec, true, NewStream { host: "yes.test".into(), tls: true, ..stream() });
        let no = StreamTap::open(&rec, true, stream());
        let off = StreamTap::open(&rec, false, NewStream { host: "yes.test".into(), ..stream() });
        assert!(yes.rec.is_some() && no.rec.is_none() && off.rec.is_none());
        // A stream that is not recorded is still counted.
        no.chunk(true, b"abc");
        assert_eq!(no.totals(), (3, 0));
        assert_eq!(seen.lock()[0], ("https".to_string(), "yes.test".to_string(), 9, None));
    }
}
