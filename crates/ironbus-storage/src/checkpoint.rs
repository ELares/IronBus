// SPDX-License-Identifier: MIT OR Apache-2.0
//! A crash-safe checkpoint for small durable state (the committed consumer cursor, and
//! later the resilience counters).
//!
//! The checkpoint is two fixed-size slots. Each write goes to the slot the sequence
//! number selects, alternating, and is CRC32C-protected over its sequence, length, and
//! payload. On recovery the higher-sequence slot whose CRC validates wins; a slot torn by
//! a crash mid-write fails its CRC and is ignored, so the previous slot survives. The
//! checkpoint may therefore regress to an earlier value after a crash, never to a torn or
//! invented one: for an at-least-once cursor that just means some already-processed
//! messages redeliver, which is safe. It never advances past a value that was not fully,
//! durably written.

use crate::io::RandomAccessFile;
use crate::segment::StorageError;
use ironbus_core::segment::SegmentError;

/// The most payload bytes a checkpoint slot holds (room for the committed offset plus the
/// resilience counters that extend it later).
pub const MAX_PAYLOAD: usize = 64;

const SEQ_LEN: usize = 8;
const LEN_LEN: usize = 2;
const CRC_LEN: usize = 4;
/// Bytes per slot: sequence, payload length, payload, CRC.
const SLOT_LEN: usize = SEQ_LEN + LEN_LEN + MAX_PAYLOAD + CRC_LEN;
/// The checkpoint file is two slots.
pub const CHECKPOINT_LEN: u64 = (SLOT_LEN * 2) as u64;

/// Reads `[seq, len, payload]` from a slot and returns the payload if the slot is valid: a
/// nonzero sequence, an in-range length, and a matching CRC over the meaningful bytes.
fn decode_slot(slot: &[u8]) -> Option<(u64, Vec<u8>)> {
    if slot.len() != SLOT_LEN {
        return None;
    }
    let seq = u64::from_le_bytes(slot[0..SEQ_LEN].try_into().ok()?);
    if seq == 0 {
        return None; // sequence 0 means "never written"
    }
    let len = usize::from(u16::from_le_bytes(
        slot[SEQ_LEN..SEQ_LEN + LEN_LEN].try_into().ok()?,
    ));
    if len > MAX_PAYLOAD {
        return None;
    }
    let payload_start = SEQ_LEN + LEN_LEN;
    let crc_start = payload_start + MAX_PAYLOAD;
    let stored_crc = u32::from_le_bytes(slot[crc_start..crc_start + CRC_LEN].try_into().ok()?);
    // The CRC covers the sequence, the length field, and the meaningful payload bytes
    // (the padding and the CRC field itself are excluded).
    if crc32c::crc32c(&slot[0..payload_start + len]) != stored_crc {
        return None;
    }
    Some((seq, slot[payload_start..payload_start + len].to_vec()))
}

fn encode_slot(seq: u64, payload: &[u8]) -> [u8; SLOT_LEN] {
    let mut slot = [0u8; SLOT_LEN];
    slot[0..SEQ_LEN].copy_from_slice(&seq.to_le_bytes());
    // payload.len() <= MAX_PAYLOAD is guaranteed by the caller, so this conversion fits.
    debug_assert!(payload.len() <= MAX_PAYLOAD, "encode_slot payload over cap");
    let len = payload.len();
    let len_field = u16::try_from(len).unwrap_or(u16::MAX);
    slot[SEQ_LEN..SEQ_LEN + LEN_LEN].copy_from_slice(&len_field.to_le_bytes());
    let payload_start = SEQ_LEN + LEN_LEN;
    slot[payload_start..payload_start + len].copy_from_slice(payload);
    let crc = crc32c::crc32c(&slot[0..payload_start + len]);
    let crc_start = payload_start + MAX_PAYLOAD;
    slot[crc_start..crc_start + CRC_LEN].copy_from_slice(&crc.to_le_bytes());
    slot
}

/// A two-slot crash-safe checkpoint over a [`RandomAccessFile`].
#[derive(Debug)]
pub struct Checkpoint<F: RandomAccessFile> {
    file: F,
    next_seq: u64,
}

impl<F: RandomAccessFile> Checkpoint<F> {
    /// Opens a checkpoint file, reading both slots to recover the latest durable value.
    /// A fresh (zeroed or short) file recovers nothing. Returns the checkpoint plus the
    /// recovered payload, if any.
    ///
    /// The caller owns the file's existence: it must create the file (e.g. via
    /// [`crate::fs::Filesystem::create_new`]) and fsync the parent directory (so the file
    /// survives a power loss right after creation) before opening it here.
    ///
    /// # Errors
    /// Propagates an IO error.
    pub fn open(file: F) -> Result<(Checkpoint<F>, Option<Vec<u8>>), StorageError> {
        let len = file.len()?;
        let mut buf = vec![0u8; SLOT_LEN * 2];
        if len >= CHECKPOINT_LEN {
            file.read_exact_at(&mut buf, 0)?;
        }
        let a = decode_slot(&buf[0..SLOT_LEN]);
        let b = decode_slot(&buf[SLOT_LEN..SLOT_LEN * 2]);
        // The higher valid sequence wins.
        let best = match (a, b) {
            (Some((sa, pa)), Some((sb, pb))) => {
                if sa >= sb {
                    Some((sa, pa))
                } else {
                    Some((sb, pb))
                }
            }
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        };
        let (next_seq, payload) = match best {
            Some((seq, payload)) => (
                seq.checked_add(1).ok_or(StorageError::SegmentFull)?,
                Some(payload),
            ),
            None => (1, None),
        };
        Ok((Checkpoint { file, next_seq }, payload))
    }

    /// Durably writes a new checkpoint payload (fsync). The previous value remains intact
    /// in the other slot until this one is durable, so a crash mid-write never loses it.
    ///
    /// # Errors
    /// Returns [`StorageError::Segment`] with [`SegmentError::Truncated`] if the payload
    /// exceeds [`MAX_PAYLOAD`], or an IO error.
    pub fn write(&mut self, payload: &[u8]) -> Result<(), StorageError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(StorageError::Segment(SegmentError::Truncated));
        }
        let seq = self.next_seq;
        let slot_index = seq % 2;
        let offset = slot_index * SLOT_LEN as u64;
        let slot = encode_slot(seq, payload);
        self.file.write_all_at(&slot, offset)?;
        self.file.sync_all()?;
        self.next_seq = seq.checked_add(1).ok_or(StorageError::SegmentFull)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::InMemoryFile;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn fresh() -> Arc<InMemoryFile> {
        Arc::new(InMemoryFile::new())
    }

    fn reopen(file: &Arc<InMemoryFile>) -> Option<Vec<u8>> {
        Checkpoint::open(Arc::clone(file)).unwrap().1
    }

    #[test]
    fn a_fresh_checkpoint_recovers_nothing() {
        assert_eq!(reopen(&fresh()), None);
    }

    #[test]
    fn write_then_reopen_round_trips() {
        let file = fresh();
        let (mut cp, recovered) = Checkpoint::open(Arc::clone(&file)).unwrap();
        assert_eq!(recovered, None);
        cp.write(b"hello").unwrap();
        assert_eq!(reopen(&file), Some(b"hello".to_vec()));
    }

    #[test]
    fn the_latest_of_several_writes_wins() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        for v in [&b"one"[..], b"two", b"three", b"four"] {
            cp.write(v).unwrap();
        }
        assert_eq!(reopen(&file), Some(b"four".to_vec()));
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"").unwrap();
        assert_eq!(reopen(&file), Some(Vec::new()));
    }

    #[test]
    fn a_payload_over_the_cap_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        let big = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            cp.write(&big),
            Err(StorageError::Segment(SegmentError::Truncated))
        ));
    }

    #[test]
    fn a_torn_newest_slot_falls_back_to_the_previous_value() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"first").unwrap(); // seq 1 -> slot 1
        cp.write(b"second").unwrap(); // seq 2 -> slot 0
                                      // Corrupt slot 0 (the newest, seq 2): flip a payload byte.
        let mut bytes = file.snapshot();
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        // Recovery regresses to the previous durable value, never a torn one.
        assert_eq!(reopen(&file), Some(b"first".to_vec()));
    }

    #[test]
    fn both_slots_torn_recovers_nothing() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"a").unwrap();
        cp.write(b"b").unwrap();
        let mut bytes = file.snapshot();
        // Corrupt a payload byte in both slots.
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        bytes[SLOT_LEN + SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(reopen(&file), None);
    }

    #[test]
    fn power_loss_on_an_unsynced_write_falls_back_to_the_prior_durable_slot() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"v1").unwrap(); // seq 1 -> slot 1, synced
        cp.write(b"v2").unwrap(); // seq 2 -> slot 0, synced
                                  // An in-flight seq-3 write to its alternating slot (slot 1), NOT synced.
        let in_flight = encode_slot(3, b"v3-lost");
        file.write_all_at(&in_flight, SLOT_LEN as u64).unwrap(); // seq 3 -> slot 1
        file.simulate_power_loss();
        // The lost write reverts slot 1 to its durable seq-1 value; recovery picks the
        // higher durable sequence (slot 0, seq 2), exercising the real fallback.
        assert_eq!(reopen(&file), Some(b"v2".to_vec()));
    }

    #[test]
    fn consecutive_writes_alternate_slots() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"s1").unwrap(); // seq 1 -> slot 1
        cp.write(b"s2").unwrap(); // seq 2 -> slot 0
        let bytes = file.snapshot();
        // The two writes landed in DIFFERENT slots (so one torn write never destroys both).
        assert_eq!(decode_slot(&bytes[0..SLOT_LEN]), Some((2, b"s2".to_vec())));
        assert_eq!(
            decode_slot(&bytes[SLOT_LEN..SLOT_LEN * 2]),
            Some((1, b"s1".to_vec()))
        );
    }

    #[test]
    fn a_max_size_payload_round_trips() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        let payload = vec![0x5a; MAX_PAYLOAD];
        cp.write(&payload).unwrap();
        assert_eq!(reopen(&file), Some(payload));
    }

    #[test]
    fn a_corrupted_length_field_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"value").unwrap(); // seq 1 -> slot 1
        let mut bytes = file.snapshot();
        bytes[SLOT_LEN + SEQ_LEN] ^= 0xff; // flip the length field in slot 1
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(
            reopen(&file),
            None,
            "a tampered length fails the CRC or the bound"
        );
    }

    #[test]
    fn a_corrupted_sequence_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"value").unwrap(); // seq 1 -> slot 1
        let mut bytes = file.snapshot();
        bytes[SLOT_LEN + 1] ^= 0xff; // flip a high sequence byte in slot 1 (CRC covers seq)
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(reopen(&file), None);
    }

    proptest! {
        /// Arbitrary single-byte corruption anywhere in the checkpoint file can only LOSE
        /// the cursor or return a genuinely-written value, never fabricate one. For any short
        /// run of writes followed by one flipped byte at an arbitrary offset (which lands in
        /// the payload region for some inputs and the seq/len/crc region for others, so the
        /// corruption-tolerance logic is reached across the input space), `Checkpoint::open`
        /// must not panic and must return either `None` or a payload byte-equal to one that
        /// was actually written. A torn, partial, or invented payload is a failure.
        #[test]
        fn single_byte_corruption_never_fabricates_a_payload(
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD),
                1..6,
            ),
            idx in any::<prop::sample::Index>(),
            xor in 1u8..=255,
        ) {
            let file = fresh();
            let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
            for p in &payloads {
                cp.write(p).unwrap();
            }

            // Flip one byte at an arbitrary offset anywhere in the fixed-size file.
            let mut bytes = file.snapshot();
            prop_assert_eq!(bytes.len() as u64, CHECKPOINT_LEN);
            let pos = idx.index(bytes.len());
            bytes[pos] ^= xor;
            file.set_len(0).unwrap();
            file.write_all_at(&bytes, 0).unwrap();
            file.sync_data().unwrap();

            // open must not panic; whatever it returns must be a value we actually wrote.
            let recovered = Checkpoint::open(Arc::clone(&file)).unwrap().1;
            if let Some(payload) = recovered {
                prop_assert!(
                    payloads.iter().any(|p| p == &payload),
                    "fabricated a payload never written: {payload:?}",
                );
            }
        }
    }
}
