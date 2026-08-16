// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag's cells into a graph, once its header has been checked.

#[cfg(feature = "parallel")]
use std::num::NonZeroUsize;
use std::sync::Arc;
#[cfg(feature = "parallel")]
use std::sync::OnceLock;

use super::{bit_len, read_header, Header, ParseOptions, Reader, MAX_DEPTH};
use crate::cell::cell::{
    summarize, Cell, CellType, Identity, Payload, Refs, Span, MAX_BITS, MAX_REFS,
};
use crate::cell::error::CellError;

/// A cell as read from the bag, with its references still as indices and its bytes still
/// in the bag.
///
/// The data and the stored hashes are where they were rather than copied out. A bag is one
/// run of bytes and every cell's contents are already inside it, so a read that copies them
/// out pays an allocation and a copy per cell for bytes it is holding either way.
struct RawCell {
    data: Span,
    bits: u16,
    /// Where each reference points, as a position among the bag's cells.
    ///
    /// Inline, because a vector here is an allocation per cell for at most four small
    /// numbers, and a bag is bounded well inside what they fit in.
    refs: [u32; MAX_REFS],
    ref_count: u8,
    cell_type: CellType,
    level_mask: u8,
    /// Where the hashes and depths the cell carried ahead of its data sit, when it carried them.
    stored: Option<Span>,
}

impl RawCell {
    /// The positions this cell references, in order.
    fn refs(&self) -> &[u32] {
        // `ref_count` is held to MAX_REFS when the cell is read, so the fallback is
        // unreachable; taking it would build a cell with fewer references than it declared,
        // which hashes to a different identity.
        self.refs.get(..usize::from(self.ref_count)).unwrap_or(&[])
    }
}

/// Parses a bag of cells and returns its root cells.
///
/// A bag holds a whole cell graph plus the indices of the roots it is read from. Most
/// bags have one root; a liteserver's account proof has two.
///
/// # Errors
///
/// Returns [`CellError::NotABagOfCells`] if the magic does not match,
/// [`CellError::Truncated`] if the bytes end early, [`CellError::Header`] if a header
/// field is out of range, [`CellError::BadReference`] if a reference is out of range or
/// does not point forward, [`CellError::Malformed`] if a cell's descriptors and data
/// disagree, [`CellError::TooManyCells`] past [`MAX_CELLS`](super::MAX_CELLS), or
/// [`CellError::TooDeep`] past [`MAX_DEPTH`](super::MAX_DEPTH).
///
/// # Examples
///
/// ```
/// use ton_net::cell::parse_boc;
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// assert_eq!(roots.len(), 1);
/// assert_eq!(roots[0].data(), &[0xab]);
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
pub fn parse_boc(bytes: &[u8]) -> Result<Vec<Cell>, CellError> {
    parse_boc_with(bytes, &ParseOptions::default())
}

/// Parses a bag of cells under bounds the caller has narrowed.
///
/// This is [`parse_boc`] with the crate's own bounds tightened. Under
/// [`ParseOptions::default`] the two admit and refuse exactly the same bags, and nothing
/// `options` can carry widens what is taken, so this door is never the looser of the two.
///
/// # Errors
///
/// As [`parse_boc`], and [`CellError::TooManyCells`] where `options` names a lower ceiling
/// than the bag needs. The error reports the ceiling that refused it rather than the
/// crate's, so a refusal names the bound the caller set.
///
/// # Examples
///
/// ```
/// use ton_net::cell::{parse_boc_with, CellError, ParseOptions};
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let options = ParseOptions::default().with_max_cells(0);
/// assert_eq!(
///     parse_boc_with(&bytes, &options),
///     Err(CellError::TooManyCells { limit: 0 })
/// );
/// ```
pub fn parse_boc_with(bytes: &[u8], options: &ParseOptions) -> Result<Vec<Cell>, CellError> {
    let mut reader = Reader { bytes, at: 0 };
    let header = read_header(&mut reader, bytes, *options)?;
    read_and_build(&mut reader, &header)
}

/// Reads a bag's cells into raw form, references still as indices, and checks each cell's
/// shape as it goes.
///
/// `reader` sits at the first cell and `header` carries the counts the reads below trust,
/// which [`read_header`] has already held to the bytes. The raw cells come back in bag
/// order, every cell ahead of the ones it references.
fn read_raw(reader: &mut Reader<'_>, header: &Header) -> Result<Vec<RawCell>, CellError> {
    let count = header.count;
    let ref_size = header.ref_size;

    let mut raw = Vec::with_capacity(count);
    for index in 0..count {
        let d1 = reader.byte()?;
        let d2 = reader.byte()?;
        // The field is three bits wide and the cell model allows four references, so the
        // top three values describe a cell no TON implementation will build.
        let ref_count = usize::from(d1 & 7);
        if ref_count > MAX_REFS {
            return Err(CellError::Malformed("cell has more than four references"));
        }
        let exotic = d1 & 8 != 0;
        let level_mask = d1 >> 5;

        // A cell may carry its own hashes and depths ahead of its data, one of each per
        // level its mask marks and one more besides. A whole block arrives this way; a
        // Merkle proof does not. None of it is taken on trust: it is checked against what
        // the cell's own contents give, so a bag that describes itself wrongly is refused.
        let stored = if d1 & super::WITH_HASHES != 0 {
            let per_level = level_mask.count_ones() as usize + 1;
            let at = reader.consumed();
            let taken = reader.take(per_level * (32 + 2))?;
            Some(Span::new(at, taken.len())?)
        } else {
            None
        };

        let at = reader.consumed();
        let data = reader.take(usize::from((d2 >> 1) + (d2 & 1)))?;
        let span = Span::new(at, data.len())?;
        let bits = bit_len(d2, data)?;
        if bits > MAX_BITS {
            return Err(CellError::Malformed("cell holds more than 1023 bits"));
        }
        let cell_type = classify(exotic, data, level_mask, ref_count)?;

        let mut refs = [0u32; MAX_REFS];
        for slot in refs.get_mut(..ref_count).ok_or(CellError::BadReference)? {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "ref_size is at most 4, so this is under 2^32"
            )]
            let target = reader.uint(ref_size)? as usize;
            // References point strictly forward, which is what keeps the graph acyclic.
            if target >= count || target <= index {
                return Err(CellError::BadReference);
            }
            *slot = u32::try_from(target).map_err(|_| CellError::BadReference)?;
        }

        raw.push(RawCell {
            data: span,
            bits,
            refs,
            #[allow(
                clippy::cast_possible_truncation,
                reason = "held to MAX_REFS above, so this is at most four"
            )]
            ref_count: ref_count as u8,
            cell_type,
            level_mask,
            stored,
        });
    }
    Ok(raw)
}

/// The failure a pass reports: whichever of the cells it judged sits at the lowest index.
///
/// A pass that returned as soon as it met a failure would report the cell its own traversal
/// reached soonest, so one bag of bytes would produce one error read descending and another
/// read in waves. NET-ADR-012 fixes the rule instead: the lowest index wins, whatever order
/// the work ran in. Reaching it costs a pass that carries on over a bag it is going to
/// refuse anyway.
///
/// A cell is judged once the cells it references have been finalized, and skipped when one
/// of them produced no value, so a parent left unbuildable by a failure beneath it records
/// no failure of its own. Recording a missing child there would name the consequence in
/// place of the cause, and would name it at a lower index, which under this rule is the
/// index that wins.
#[derive(Default)]
struct Lowest {
    held: Option<(usize, CellError)>,
}

impl Lowest {
    /// Keeps `error` if `index` is lower than the failure held so far.
    fn record(&mut self, index: usize, error: CellError) {
        if self.held.as_ref().is_none_or(|(at, _)| index < *at) {
            self.held = Some((index, error));
        }
    }

    /// The failure to report, if the pass held one.
    fn into_result(self) -> Result<(), CellError> {
        match self.held {
            Some((_, error)) => Err(error),
            None => Ok(()),
        }
    }
}

/// The structural height of each of the bag's cells, indexed by cell index, refusing a
/// graph deeper than [`MAX_DEPTH`](super::MAX_DEPTH).
///
/// A cell's height is one more than the tallest of its children's, and zero for a cell with
/// no references. References point strictly forward, which [`read_raw`] refuses a bag for
/// breaking, so a pass from the highest index down meets a child before its parent and the
/// heights accumulate in one sweep.
///
/// The sweep finishes before anything is refused, so the refusal is a property of the bag
/// rather than of where the sweep began. [`CellError::TooDeep`] carries no cell index, so
/// this is the reporting rule of [`Lowest`] holding here rather than a difference a caller
/// can see.
fn heights(raw: &[RawCell], count: usize) -> Result<Vec<usize>, CellError> {
    let mut height: Vec<usize> = vec![0; count];
    for index in (0..count).rev() {
        let Some(raw_cell) = raw.get(index) else {
            continue;
        };
        let mut tallest = 0usize;
        for &target in raw_cell.refs() {
            let below = height.get(target as usize).copied().unwrap_or(0);
            tallest = tallest.max(below + 1);
        }
        if let Some(slot) = height.get_mut(index) {
            *slot = tallest;
        }
    }
    if height.iter().any(|&at| at > MAX_DEPTH) {
        return Err(CellError::TooDeep { limit: MAX_DEPTH });
    }
    Ok(height)
}

/// The bag's cells grouped by structural height, the shortest wave first.
///
/// A cell's children are shorter than it is, so by the time a wave is reached every cell
/// it holds has its children finished. That leaves the cells inside one wave independent
/// of each other: their order within the wave is free, and so is the thread each runs on.
///
/// The shape of the bag decides how much of that is worth taking, with no test of what
/// kind of bag it is. A Merkle proof is a path, so its height runs with its cell count and
/// each wave holds about one cell. A dictionary over n entries is about log n tall, so its
/// waves hold a large part of the bag at once.
struct Waves {
    /// Cell indices, ascending inside a wave, waves shortest first.
    order: Vec<usize>,
    /// Where each wave begins in `order`, and one entry past the tallest holding the cell
    /// count, so wave k is `order[starts[k]..starts[k + 1]]`.
    starts: Vec<usize>,
}

impl Waves {
    /// Buckets the cells by height, with a counting sort over the heights.
    fn by_height(height: &[usize]) -> Self {
        let tallest = height.iter().copied().max().unwrap_or(0);
        // One slot per height, and one past the tallest to close the last wave.
        let mut starts = vec![0usize; tallest + 2];
        for &at in height {
            if let Some(slot) = starts.get_mut(at + 1) {
                *slot += 1;
            }
        }
        for k in 1..starts.len() {
            let carried = starts.get(k - 1).copied().unwrap_or(0);
            if let Some(slot) = starts.get_mut(k) {
                *slot += carried;
            }
        }

        // Each wave's beginning is spent as a cursor, so walking the cells in index order
        // leaves each wave ascending and leaves `starts[k]` holding where wave k ends.
        let mut order = vec![0usize; height.len()];
        for (index, &at) in height.iter().enumerate() {
            let Some(cursor) = starts.get_mut(at) else {
                continue;
            };
            let slot = *cursor;
            *cursor += 1;
            if let Some(place) = order.get_mut(slot) {
                *place = index;
            }
        }

        // A wave ends where the next begins, so one shift puts the beginnings back and the
        // count stays where it was, closing the tallest wave.
        for k in (1..starts.len()).rev() {
            let ended = starts.get(k - 1).copied().unwrap_or(0);
            if let Some(slot) = starts.get_mut(k) {
                *slot = ended;
            }
        }
        if let Some(first) = starts.first_mut() {
            *first = 0;
        }

        Self { order, starts }
    }

    /// The waves in order, shortest first.
    fn iter(&self) -> impl Iterator<Item = &[usize]> {
        self.starts.windows(2).filter_map(|pair| {
            let from = pair.first().copied()?;
            let to = pair.get(1).copied()?;
            self.order.get(from..to)
        })
    }

    /// One cell per wave, highest index first: the order a bag finalized in a single
    /// descending pass runs in.
    ///
    /// The comparison the parity gate makes rests on this being that order and not a
    /// rearrangement of it, so nothing but the plan differs between the two runs.
    #[cfg(test)]
    fn descending(count: usize) -> Self {
        Self {
            order: (0..count).rev().collect(),
            starts: (0..=count).collect(),
        }
    }
}

/// The fewest cells a worker is handed before another thread is worth its coordination.
///
/// A floor rather than a calibration. It is chosen so that the work given to a thread is
/// large next to the cost of starting one, and NET-ADR-012 forbids stating the ratio as a
/// duration taken on one machine, so none is stated. Its second job is to keep the
/// captured fixtures on the counted path: no bag under twice this many cells splits, and
/// the gate that reads the fixtures counts on the thread it runs on. What a split costs is
/// counted by a second gate, over bags cut around twice this width rather than captured, on
/// every thread the split reaches.
const CELLS_PER_WORKER: usize = 1024;

/// How many threads this machine reports, or one where it reports none.
///
/// The attribute rather than the `cfg!` macro, because the macro leaves the body in every
/// build: a target with no threads would carry the call and reach it only through a
/// condition that is always false, which is a capability compiled in for nothing.
#[cfg(feature = "parallel")]
fn parallelism() -> usize {
    static CORES: OnceLock<usize> = OnceLock::new();
    *CORES.get_or_init(|| std::thread::available_parallelism().map_or(1, NonZeroUsize::get))
}

/// One worker, which is what a build with no thread to spawn has.
#[cfg(not(feature = "parallel"))]
fn parallelism() -> usize {
    1
}

/// How many threads a wave of `width` cells is split across.
///
/// The whole of the dispatch decision. Two numbers reach it, the wave's width and what
/// [`parallelism`] reports, and the width is the one the bag has any say in: nothing here
/// asks what kind of bag it is. A wave is split only once its width holds a full
/// [`CELLS_PER_WORKER`] for every worker started, so a bag shaped like a path answers one
/// for every wave it has and runs with no coordination at all, while a bag whose waves are
/// several workers wide answers the smaller of what the width affords and what the machine
/// reports.
///
/// The shares themselves are cut from the width rather than measured out at that size, so
/// a width the worker count does not divide gives shares differing by fewer cells than
/// there are workers, and the last of them can fall under a full [`CELLS_PER_WORKER`].
fn workers_for(width: usize) -> usize {
    // The width is asked first, and the machine only if the width could use an answer. A
    // wave under two full shares is running on the caller's thread whatever the machine
    // says, and asking anyway is not free: the reading is taken once and kept, so the first
    // bag read in a process would pay for it and every later one would not. A bag's cost
    // has to be the same every time it is read, which `tests/allocations.rs` holds it to.
    let affords = width / CELLS_PER_WORKER;
    if affords < 2 {
        return 1;
    }
    parallelism().min(affords).max(1)
}

/// What finalizing one wave produced, against the cell index each outcome came from.
type WaveOutcomes<T> = Vec<(usize, Result<Option<T>, CellError>)>;

/// Hands a wave to several threads, or reports that it is not wide enough to be worth it.
///
/// The workers read the cells already held and write nothing of the graph, so what comes
/// back is the same list of outcomes the wave would have produced here, against the index
/// each came from.
///
/// The outcomes go straight into one buffer of the wave's own length rather than into a
/// list per worker that is then joined into one. The two are cut by the same arithmetic
/// over slices of the same length, so worker k writes exactly the outcomes of the cells it
/// was handed and no two workers hold overlapping slices, which is what makes the writes
/// disjoint and lets the borrow checker see that they are. `chunks_mut` is what carries
/// that, rather than a pointer the crate root would refuse: it splits the buffer once and
/// no chunk is reachable from any other.
///
/// The buffer is filled with a placeholder outcome and overwritten, because a wave is cut
/// into as many chunks as `wave.chunks` yields and every slot of every chunk is written
/// before it is read. `Ok(None)` is the placeholder, which asks nothing of `T` and is the
/// same value a cell whose child produced nothing would leave there anyway.
///
/// A wave with no cells is refused along with the widths one worker takes. The share
/// below is the width divided among the workers, which is zero cells there, and a wave cut
/// into shares of nothing has no last share to stop at. Nothing arrives here that way from
/// [`run_wave`], since [`workers_for`] answers one for a width of zero, so what the guard
/// covers is a caller passing the worker count itself.
#[cfg(feature = "parallel")]
fn split_across_workers<T, F>(
    wave: &[usize],
    held: &[Option<T>],
    one: &F,
    workers: usize,
) -> Option<WaveOutcomes<T>>
where
    T: Send + Sync,
    F: Fn(usize, &[Option<T>]) -> Result<Option<T>, CellError> + Sync,
{
    if workers < 2 || wave.is_empty() {
        return None;
    }
    let each = wave.len().div_ceil(workers);
    let mut produced: WaveOutcomes<T> = Vec::new();
    produced.resize_with(wave.len(), || (0, Ok(None)));
    std::thread::scope(|scope| {
        let running: Vec<_> = wave
            .chunks(each)
            .zip(produced.chunks_mut(each))
            .map(|(part, slots)| {
                scope.spawn(move || {
                    for (slot, &index) in slots.iter_mut().zip(part) {
                        *slot = (index, one(index, held));
                    }
                })
            })
            .collect();
        for worker in running {
            // A worker runs what this thread would run, which returns its failures rather
            // than unwinding. One that unwound anyway is carried on to the caller, which is
            // what the same fault on this thread would have done.
            worker
                .join()
                .unwrap_or_else(|unwound| std::panic::resume_unwind(unwound));
        }
    });
    Some(produced)
}

/// A build without the `parallel` feature keeps every wave on this thread.
#[cfg(not(feature = "parallel"))]
fn split_across_workers<T, F>(
    _wave: &[usize],
    _held: &[Option<T>],
    _one: &F,
    _workers: usize,
) -> Option<WaveOutcomes<T>> {
    None
}

/// Finalizes the cells of one wave, on this thread or across several.
///
/// Which happens is [`workers_for`]'s answer and is not visible in what this leaves
/// behind: the cells of a wave depend on no other cell in it, so `one` sees the same
/// values whichever worker calls it, and the failure that survives is picked by index
/// rather than by arrival.
fn run_wave<T, F>(wave: &[usize], held: &mut [Option<T>], lowest: &mut Lowest, one: &F)
where
    T: Send + Sync,
    F: Fn(usize, &[Option<T>]) -> Result<Option<T>, CellError> + Sync,
{
    let workers = workers_for(wave.len());
    if workers > 1 {
        if let Some(produced) = split_across_workers(wave, held, one, workers) {
            for (index, outcome) in produced {
                keep(held, lowest, index, outcome);
            }
            return;
        }
    }
    for &index in wave {
        let outcome = one(index, held);
        keep(held, lowest, index, outcome);
    }
}

/// Finalizes a bag's cells wave by wave, and reports the lowest failure among them.
///
/// `one` finalizes a single cell over the values already held, and is the same call a
/// pass running the cells one after another would make. Waves choose when each call
/// happens and nothing else, which is why running them in one order or another cannot
/// reach a caller.
fn finalize<T, F>(count: usize, waves: &Waves, one: &F) -> (Vec<Option<T>>, Lowest)
where
    T: Clone + Send + Sync,
    F: Fn(usize, &[Option<T>]) -> Result<Option<T>, CellError> + Sync,
{
    let mut held: Vec<Option<T>> = vec![None; count];
    let mut lowest = Lowest::default();
    for wave in waves.iter() {
        run_wave(wave, &mut held, &mut lowest, one);
    }
    (held, lowest)
}

/// The bag's root cells, read from the positions the header names.
fn roots<T: Clone>(built: &[Option<T>], header: &Header) -> Result<Vec<T>, CellError> {
    header
        .root_list
        .iter()
        .map(|&index| {
            built
                .get(index)
                .and_then(Option::as_ref)
                .cloned()
                .ok_or(CellError::BadReference)
        })
        .collect()
}

/// Builds one cell from its raw form, over the cells already built.
///
/// Returns `Ok(None)` when a cell this one references has no value in `built`. References
/// point strictly forward, which [`read_raw`] refuses a bag for breaking, and a cell at a
/// higher index is finalized first, so an empty slot was reached and produced no value: it
/// failed, or a cell beneath it did. A cell's identity is hashed over its children's
/// identities, so there is none to compute here, and what [`Lowest`] wants is the earlier
/// failure below rather than the gap this call found.
fn build_one(
    raw_cell: &RawCell,
    payload: &Arc<[u8]>,
    built: &[Option<Cell>],
) -> Result<Option<Cell>, CellError> {
    let mut refs = Refs::None;
    for &target in raw_cell.refs() {
        match built.get(target as usize) {
            Some(Some(child)) => refs.push(child.clone())?,
            Some(None) => return Ok(None),
            // read_raw holds every reference under the bag's cell count, so a slot past
            // the end is unreachable rather than a shape a bag can ask for.
            None => return Err(CellError::BadReference),
        }
    }
    let cell = Cell::from_parts(
        Payload::window(payload, raw_cell.data)?,
        raw_cell.bits,
        refs,
        raw_cell.cell_type,
        raw_cell.level_mask,
    )?;
    if let Some(stored) = &raw_cell.stored {
        check_stored(cell.identity(), stored.of(payload)?)?;
    }
    Ok(Some(cell))
}

/// Summarizes one cell from its raw form, over the identities already computed.
///
/// What [`build_one`] is for a graph, this is for identities alone: it keeps a summary of
/// each cell in place of the cell, and reports a missing child the same way, with
/// `Ok(None)`.
fn summarize_one(
    raw_cell: &RawCell,
    bytes: &[u8],
    computed: &[Option<Identity>],
) -> Result<Option<Identity>, CellError> {
    // The children are borrowed out of the identities already kept, so a cell costs no
    // allocation to look at.
    let unfilled = Identity::NONE;
    let mut children = [&unfilled; MAX_REFS];
    for (slot, &target) in children.iter_mut().zip(raw_cell.refs()) {
        match computed.get(target as usize) {
            Some(Some(child)) => *slot = child,
            Some(None) => return Ok(None),
            // Unreachable for the reason build_one gives.
            None => return Err(CellError::BadReference),
        }
    }
    let children = children
        .get(..raw_cell.refs().len())
        .ok_or(CellError::BadReference)?;
    let identity = summarize(
        raw_cell.data.of(bytes)?,
        raw_cell.bits,
        children,
        raw_cell.cell_type,
        raw_cell.level_mask,
    )?;
    if let Some(stored) = &raw_cell.stored {
        check_stored(&identity, stored.of(bytes)?)?;
    }
    Ok(Some(identity))
}

/// Reads the cells of a bag whose header has been read, and returns its roots.
///
/// The cells are finalized in the waves of [`Waves::by_height`], so a cell is built after
/// the cells it references and before anything that references it.
pub(super) fn read_and_build(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<Cell>, CellError> {
    // One buffer for the bag, shared by every cell built from it, in place of a copy of
    // each cell's bytes.
    let payload: Arc<[u8]> = Arc::from(reader.bytes);
    let raw = read_raw(reader, header)?;
    let waves = Waves::by_height(&heights(&raw, header.count)?);
    build_planned(&raw, &payload, &waves, header)
}

/// Builds a bag's cells under a plan and returns its roots.
///
/// The plan chooses the order alone. Position k of the vector this fills holds cell k, so
/// a reference is read at the index it names whichever wave built it.
fn build_planned(
    raw: &[RawCell],
    payload: &Arc<[u8]>,
    waves: &Waves,
    header: &Header,
) -> Result<Vec<Cell>, CellError> {
    let one = |index: usize, built: &[Option<Cell>]| match raw.get(index) {
        Some(raw_cell) => build_one(raw_cell, payload, built),
        // read_raw returns one raw cell per cell the header declared, so a plan cannot
        // name a position outside it.
        None => Err(CellError::BadReference),
    };
    let (built, lowest) = finalize(header.count, waves, &one);
    lowest.into_result()?;
    roots(&built, header)
}

/// Records what finalizing a cell produced: the value, a skip where a cell below it
/// failed, or the failure against the index it came from.
fn keep<T>(
    built: &mut [Option<T>],
    lowest: &mut Lowest,
    index: usize,
    outcome: Result<Option<T>, CellError>,
) {
    match outcome {
        Ok(Some(value)) => {
            if let Some(slot) = built.get_mut(index) {
                *slot = Some(value);
            }
        }
        Ok(None) => {}
        Err(error) => lowest.record(index, error),
    }
}

/// Hash-verifies a bag's cells without building its graph, and returns its roots' identities.
///
/// This reads and checks every cell exactly as [`read_and_build`] does, but keeps a summary
/// per cell, tens of bytes, rather than a whole cell, so a large bag can be verified and its
/// root hashes read at a fraction of the memory the graph would take. The summaries feed each
/// other bottom up through [`summarize`], the same hashing a built cell runs.
///
/// # Errors
///
/// As [`read_and_build`], for the cells it reads and the identities it computes.
pub(super) fn verify_roots(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<[u8; 32]>, CellError> {
    // Nothing is built here, so the bag's own bytes serve and no buffer is taken.
    let bytes = reader.bytes;
    let raw = read_raw(reader, header)?;
    let waves = Waves::by_height(&heights(&raw, header.count)?);
    verify_planned(&raw, bytes, &waves, header)
}

/// Summarizes a bag's cells under a plan and returns its roots' representation hashes.
///
/// The identity-side counterpart of [`build_planned`], down to the plan it runs and the
/// index each value is held at.
fn verify_planned(
    raw: &[RawCell],
    bytes: &[u8],
    waves: &Waves,
    header: &Header,
) -> Result<Vec<[u8; 32]>, CellError> {
    let one = |index: usize, computed: &[Option<Identity>]| match raw.get(index) {
        Some(raw_cell) => summarize_one(raw_cell, bytes, computed),
        // Unreachable for the reason build_planned gives.
        None => Err(CellError::BadReference),
    };
    let (identities, lowest) = finalize(header.count, waves, &one);
    lowest.into_result()?;

    let roots = roots(&identities, header)?;
    Ok(roots.iter().map(|identity| *identity.repr_hash()).collect())
}

/// A bag's cells as they were read, before any of them is built.
///
/// Reading a bag and building its cells are two costs, and only the second one is per cell.
/// A reader that keeps this has paid the first in full, which is what lets it build cell
/// after cell without going back to the bytes.
pub(super) struct RawCells {
    cells: Vec<RawCell>,
    /// The bag the spans above are windows on, kept because the cells built from it point
    /// into it.
    payload: Arc<[u8]>,
}

impl RawCells {
    /// How many cells the bag holds.
    pub(super) fn len(&self) -> usize {
        self.cells.len()
    }
}

/// Reads and checks every cell of a bag whose header has been read, building none of them.
///
/// # Errors
///
/// As [`read_and_build`], for the cells it reads.
pub(super) fn read_cells(reader: &mut Reader<'_>, header: &Header) -> Result<RawCells, CellError> {
    let payload: Arc<[u8]> = Arc::from(reader.bytes);
    let cells = read_raw(reader, header)?;
    heights(&cells, header.count)?;
    Ok(RawCells { cells, payload })
}

/// The cells built from a bag so far, and the scratch a repeated build reuses.
///
/// A walk marks what it reaches with a generation number rather than a flag, so opening one
/// costs a counter where clearing a flag vector would cost the length of the bag. That is
/// what keeps reading one cell proportional to its own subtree rather than to the bag, however
/// many cells have been read before it.
pub(super) struct Build {
    built: Vec<Option<Cell>>,
    /// The walk that last reached each cell. Equal to `generation` means reached by this one.
    seen: Vec<u32>,
    generation: u32,
    /// How many cells are held.
    kept: usize,
    /// How many cells have been built, which rises above `kept` only when a cell already
    /// built is built again. That is the one thing this type exists to avoid, and nothing
    /// else here can be asked about it: a rebuilt cell is equal to the one it replaced and
    /// takes the same slot, so only a count of the work done says it happened.
    builds: usize,
}

impl Build {
    /// Room to build the cells of a bag holding `count` of them, with none built.
    pub(super) fn new(count: usize) -> Self {
        Self {
            built: vec![None; count],
            seen: vec![0; count],
            generation: 0,
            kept: 0,
            builds: 0,
        }
    }

    /// Holds a freshly built cell at `position`, counting the build.
    fn keep(&mut self, position: usize, cell: Cell) {
        self.builds += 1;
        if let Some(slot) = self.built.get_mut(position) {
            if slot.is_none() {
                self.kept += 1;
            }
            *slot = Some(cell);
        }
    }

    /// The cell at `index`, if it has been built.
    pub(super) fn get(&self, index: usize) -> Option<Cell> {
        self.built.get(index).cloned().flatten()
    }

    /// How many cells have been built and kept.
    pub(super) fn count(&self) -> usize {
        self.kept
    }

    /// How many cells have been built, whether or not they were already built once.
    pub(super) fn builds(&self) -> usize {
        self.builds
    }

    /// Opens a walk and returns the generation it marks cells with.
    fn open_walk(&mut self) -> u32 {
        if let Some(next) = self.generation.checked_add(1) {
            self.generation = next;
        } else {
            // A generation that wrapped would read a mark left by an older walk as one of its
            // own, so the marks go back to nothing and counting starts again.
            self.seen.fill(0);
            self.generation = 1;
        }
        self.generation
    }
}

/// Builds the cell at `index` and every cell it reaches that is not built already, keeping
/// each one.
///
/// `index` is a position among the bag's cells in stored order, the roots first. References
/// point strictly forward, which [`read_cells`] has already checked, so a cell's subtree is a
/// set of cells at higher indices and building in descending order reaches every child before
/// its parent.
///
/// A cell is only ever built together with its whole subtree, so one already built needs
/// nothing below it walked again.
///
/// # Errors
///
/// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
/// [`read_and_build`], for the cells it builds.
pub(super) fn build_at(raw: &RawCells, state: &mut Build, index: usize) -> Result<Cell, CellError> {
    if index >= raw.cells.len() {
        return Err(CellError::BadReference);
    }
    if let Some(cell) = state.get(index) {
        return Ok(cell);
    }

    // Walk what the requested cell reaches and has not been built, collecting the positions
    // rather than scanning the bag for them afterwards.
    let generation = state.open_walk();
    let mut order: Vec<usize> = Vec::new();
    let mut stack = vec![index];
    while let Some(position) = stack.pop() {
        if state.built.get(position).is_some_and(Option::is_some) {
            continue;
        }
        match state.seen.get_mut(position) {
            Some(mark) if *mark != generation => *mark = generation,
            _ => continue,
        }
        order.push(position);
        for &target in raw
            .cells
            .get(position)
            .ok_or(CellError::BadReference)?
            .refs()
        {
            stack.push(target as usize);
        }
    }
    order.sort_unstable();

    let mut lowest = Lowest::default();
    for position in order.into_iter().rev() {
        let raw_cell = raw.cells.get(position).ok_or(CellError::BadReference)?;
        match build_one(raw_cell, &raw.payload, &state.built) {
            Ok(Some(cell)) => state.keep(position, cell),
            Ok(None) => {}
            Err(error) => lowest.record(position, error),
        }
    }
    lowest.into_result()?;

    state.get(index).ok_or(CellError::BadReference)
}

/// Builds one cell of the bag, and only the cells it reaches, leaving the rest unbuilt.
///
/// This reads the bag to know its structure and to check it, builds the requested cell's
/// subtree, and drops the rest. A caller reading more than one cell of the same bag wants
/// [`read_cells`] and [`build_at`] instead, which read once and keep what they build.
///
/// # Errors
///
/// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
/// [`read_and_build`], for the cells it reads and builds.
pub(super) fn build_cell(
    reader: &mut Reader<'_>,
    header: &Header,
    index: usize,
) -> Result<Cell, CellError> {
    if index >= header.count {
        return Err(CellError::BadReference);
    }
    let raw = read_cells(reader, header)?;
    let mut state = Build::new(header.count);
    build_at(&raw, &mut state, index)
}

/// Determines a cell's kind, and holds an exotic cell to the shape that kind must have.
///
/// Every exotic kind has a fixed reference count, and a pruned branch a fixed body length
/// as well. The checks belong here, at the parse boundary, because a cell that reaches
/// [`Cell::from_parts`] is hashed, and a hash computed over a shape the cell model does
/// not define is a value no other implementation agrees with.
fn classify(
    exotic: bool,
    data: &[u8],
    level_mask: u8,
    ref_count: usize,
) -> Result<CellType, CellError> {
    if !exotic {
        return Ok(CellType::Ordinary);
    }
    let tag = *data
        .first()
        .ok_or(CellError::Malformed("exotic cell has no type byte"))?;
    let cell_type =
        CellType::from_tag(tag).ok_or(CellError::Malformed("unknown exotic cell type"))?;

    let expected_refs = match cell_type {
        CellType::Ordinary => return Ok(cell_type),
        CellType::PrunedBranch | CellType::LibraryReference => 0,
        CellType::MerkleProof => 1,
        CellType::MerkleUpdate => 2,
    };
    if ref_count != expected_refs {
        // A pruned branch is the one that matters. Its hash is computed from the hash it
        // stands in for and never from its children, so a pruned branch allowed to carry
        // children would hash the same whatever hangs beneath it: an attacker-chosen
        // collision on the value this crate calls a cell's identity.
        return Err(CellError::Malformed(
            "exotic cell has the wrong number of references",
        ));
    }

    if cell_type == CellType::PrunedBranch {
        // A pruned branch carries its level mask twice, in the descriptor and in the
        // cell body, and only the descriptor copy is hashed. Two copies that disagree
        // would leave a cell whose body says one thing and whose identity says another,
        // so the disagreement is refused rather than resolved.
        let stored = *data
            .get(1)
            .ok_or(CellError::Malformed("pruned branch has no mask byte"))?;
        if stored != level_mask {
            return Err(CellError::Malformed(
                "pruned branch mask disagrees with its descriptor",
            ));
        }
        // A pruned branch stands in for a subtree at some level, so it has to have one.
        // At level zero it stores no hash at all and answers with its own, which is a
        // shape that stands in for nothing.
        if stored == 0 {
            return Err(CellError::Malformed("pruned branch has no level"));
        }
        // One hash and one depth per marked level, after the type and mask bytes, and
        // nothing else: an exact length leaves no trailing bytes to carry a second
        // meaning past the ones the reads below index.
        let levels = stored.count_ones() as usize;
        if data.len() != 2 + levels * 34 {
            return Err(CellError::Malformed(
                "pruned branch length disagrees with its level mask",
            ));
        }
    }
    Ok(cell_type)
}

/// Holds a cell's computed identity to the hashes and depths it carried.
///
/// The stored copies are never used: the cell's identity comes from its own contents
/// either way. What they are good for is disagreement, which means the sender computed
/// something this crate did not, and there is no reading of that worth continuing from.
/// It takes the computed identity rather than a cell, so the graph-building read and the
/// identity-only read can both reach it.
fn check_stored(identity: &Identity, stored: &[u8]) -> Result<(), CellError> {
    let count = identity.count();
    if stored.len() != count * 34 {
        return Err(CellError::Malformed(
            "cell stores a different number of hashes than its level mask allows",
        ));
    }
    let missing = || CellError::Malformed("cell has fewer hashes than its level mask calls for");
    for index in 0..count {
        let hash = identity.hash(index).ok_or_else(missing)?;
        if stored.get(index * 32..index * 32 + 32) != Some(&hash[..]) {
            return Err(CellError::Malformed(
                "cell stores a hash its contents do not give",
            ));
        }
    }
    let base = count * 32;
    for index in 0..count {
        let depth = identity.depth(index).ok_or_else(missing)?;
        let at = base + index * 2;
        if stored.get(at..at + 2) != Some(&depth.to_be_bytes()[..]) {
            return Err(CellError::Malformed(
                "cell stores a depth its contents do not give",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{serialize_boc, serialize_boc_with, BocOptions, Builder};

    /// The captured mainnet account proof, read from the fixture the hostile corpus
    /// mutates so that the parity gate and that corpus work over one real bag.
    const PROOF_HEX: &str = include_str!("../../../tests/fixtures/account-proof.hex");

    /// How many levels of forks the fan bag carries above its leaves.
    ///
    /// Six puts 4096 cells in the widest wave, which is four workers' worth, so the
    /// dispatch splits it wherever the machine has the threads.
    const FAN_DEEP: u32 = 6;

    /// The refusal a cell earns by claiming a level its children do not give it.
    const BY_LEVEL: CellError =
        CellError::Malformed("cell level mask is not the one its children imply");

    /// The refusal a cell earns by storing a hash its own contents do not produce.
    const BY_HASH: CellError = CellError::Malformed("cell stores a hash its contents do not give");

    /// A fixed-seed xorshift, so a failure reproduces exactly.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            let Ok(bound) = u64::try_from(bound) else {
                return 0;
            };
            if bound == 0 {
                return 0;
            }
            usize::try_from(self.next() % bound).unwrap_or(0)
        }
    }

    /// A result taken under both plans: the waves the read path takes, then the single
    /// descending pass.
    type BothWays<T> = (Result<T, CellError>, Result<T, CellError>);

    fn unhex(text: &str) -> Vec<u8> {
        let hex: String = text
            .lines()
            .filter(|line| !line.starts_with('#'))
            .flat_map(str::chars)
            .filter(|c| !c.is_whitespace())
            .collect();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("the fixture is hex"))
            .collect()
    }

    /// A bag read to raw cells, with the bytes its cells window into.
    struct Prepared {
        raw: Vec<RawCell>,
        payload: Arc<[u8]>,
        header: Header,
    }

    /// Reads a bag as far as the pass that finalizes its cells, or reports that its bytes
    /// never got there.
    ///
    /// The header, the bag's bytes and the raw cells are read once here and handed to both
    /// plans, so the pass that finalizes is what the two runs differ in. The heights are
    /// measured again when the wave plan is built, which is that plan being made rather
    /// than an input the two runs share.
    fn prepare(bytes: &[u8]) -> Option<Prepared> {
        let mut reader = Reader { bytes, at: 0 };
        let header = read_header(&mut reader, bytes, ParseOptions::default()).ok()?;
        let payload: Arc<[u8]> = Arc::from(reader.bytes);
        let raw = read_raw(&mut reader, &header).ok()?;
        heights(&raw, header.count).ok()?;
        Some(Prepared {
            raw,
            payload,
            header,
        })
    }

    impl Prepared {
        /// The plan the read path takes.
        fn waves(&self) -> Waves {
            Waves::by_height(&heights(&self.raw, self.header.count).expect("the depth was held"))
        }

        /// The graph, built in waves and built in one descending pass.
        fn built_both_ways(&self) -> BothWays<Vec<Cell>> {
            (
                build_planned(&self.raw, &self.payload, &self.waves(), &self.header),
                build_planned(
                    &self.raw,
                    &self.payload,
                    &Waves::descending(self.header.count),
                    &self.header,
                ),
            )
        }

        /// The root hashes, verified in waves and verified in one descending pass.
        fn verified_both_ways(&self) -> BothWays<Vec<[u8; 32]>> {
            (
                verify_planned(&self.raw, &self.payload, &self.waves(), &self.header),
                verify_planned(
                    &self.raw,
                    &self.payload,
                    &Waves::descending(self.header.count),
                    &self.header,
                ),
            )
        }
    }

    /// A bag of `count` cells that reference nothing, so the whole bag is one wave.
    ///
    /// The cells named in `by_level` claim a level mask no child gives them, and those in
    /// `by_hash` carry a stored hash their contents do not produce. Two faults rather than
    /// one, because a bag failing at several cells with one message would not say which
    /// cell the reported failure came from.
    fn one_wave_bag(count: usize, by_level: &[usize], by_hash: &[usize]) -> Vec<u8> {
        let mut cells = Vec::new();
        for index in 0..count {
            let stored = by_hash.contains(&index);
            // d1 is 32 * level_mask + 8 * exotic + reference count, and bit four says the
            // cell carries its own hashes and depths ahead of its data.
            let mut d1 = 0u8;
            if by_level.contains(&index) {
                d1 |= 0x20;
            }
            if stored {
                d1 |= 0x10;
            }
            cells.push(d1);
            cells.push(0x00);
            if stored {
                cells.extend([0xaa; 34]);
            }
        }

        let mut bag = vec![0xb5, 0xee, 0x9c, 0x72, 0x02, 0x02];
        let field = |value: usize| u16::try_from(value).expect("the field fits").to_be_bytes();
        bag.extend(field(count)); // cells
        bag.extend(field(1)); // roots
        bag.extend(field(0)); // absent cells
        bag.extend(field(cells.len())); // cell area
        bag.extend(field(0)); // the root is cell zero
        bag.extend(cells);
        bag
    }

    /// A serialized bag shaped like a proof: one chain of `links` cells over a leaf, each
    /// carrying a number of its own so none of them is shared with another.
    fn path_bag(links: usize) -> Vec<u8> {
        let mut cell = Builder::new().build().expect("a leaf forms");
        for step in 0..links {
            let mut builder = Builder::new();
            builder
                .store_uint(u64::try_from(step).expect("a step fits"), 64)
                .expect("a word fits");
            builder.store_ref(cell).expect("a reference fits");
            cell = builder.build().expect("a cell forms");
        }
        serialize_boc(std::slice::from_ref(&cell)).expect("the path serializes")
    }

    /// A serialized bag shaped like a dictionary: a four-way fan `deep` levels of forks
    /// tall, again with every cell numbered so none is shared.
    /// It carries no checksum, so a flipped byte reaches the cells rather than being
    /// refused at the header.
    fn fan_bag(deep: u32) -> Vec<u8> {
        let mut serial = 0u64;
        let mut numbered = |children: &[Cell]| {
            serial += 1;
            let mut builder = Builder::new();
            builder.store_uint(serial, 64).expect("a word fits");
            for child in children {
                builder.store_ref(child.clone()).expect("a reference fits");
            }
            builder.build().expect("a cell forms")
        };

        let mut level: Vec<Cell> = (0..MAX_REFS.pow(deep)).map(|_| numbered(&[])).collect();
        while level.len() > 1 {
            level = level.chunks(MAX_REFS).map(&mut numbered).collect();
        }
        serialize_boc_with(&level, &BocOptions::default().with_checksum(false))
            .expect("the fan serializes")
    }

    /// The plan a serialized bag finalizes under.
    fn plan_for(bag: &[u8]) -> Waves {
        prepare(bag)
            .expect("the bag reaches the pass that finalizes cells")
            .waves()
    }

    #[test]
    fn the_wave_plan_and_a_single_pass_agree_on_corrupted_bags() {
        // The gate NET-ADR-012 puts on this work, and it runs over corrupted bytes rather
        // than over bags that parse: a bag with no failing cell agrees under every rule
        // for picking which failure to report, so it cannot tell the plans apart. The
        // fixture is the one the hostile corpus mutates, and the mutation is the same
        // kind, single flipped bits from a fixed seed.
        //
        // What this corpus reaches is counted rather than assumed. Of the mutations that
        // get as far as the finalizing pass, 54 are refused there, and every one of those
        // fails at a single cell: a flipped bit in a proof's data changes a hash and its
        // ancestors' hashes without refusing anything, so the cells that can be made to
        // fail here are the few carrying a descriptor the pass reads. One failure is
        // picked the same way by every rule, so what these bags settle is that the two
        // plans judge the same cells and reach the same values. Choosing between failures
        // is settled by a_wave_wide_enough_to_split_reports_the_lowest_failure, which
        // builds its bag and plants two kinds of fault, because a bag refused at one cell
        // cannot say which of several the rule picked.
        let proof = unhex(PROOF_HEX);
        let mut rng = Rng(0x1D8E_4A2B_7C36_F591);
        let mut finalized = 0usize;
        let mut refused = 0usize;

        for _ in 0..4_000 {
            let mut bytes = proof.clone();
            for _ in 0..=rng.below(3) {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
            let Some(prepared) = prepare(&bytes) else {
                continue;
            };

            let (waved, one_pass) = prepared.built_both_ways();
            assert_eq!(
                waved, one_pass,
                "the plan a bag was finalized under reached a caller"
            );
            let (waved_hashes, one_pass_hashes) = prepared.verified_both_ways();
            assert_eq!(
                waved_hashes, one_pass_hashes,
                "the plan a bag was verified under reached a caller"
            );
            // The two reads of the same bytes, held to the same refusal. A caller that
            // reads a bag for its identity alone runs the second, and a bag it accepts
            // that the first refuses is a malformed cell accepted, so this is the
            // comparison across the two paths rather than across the two plans. It has
            // something to say on the bags the pass refuses and is an equality of
            // absences on the rest.
            assert_eq!(
                waved.as_ref().err(),
                waved_hashes.as_ref().err(),
                "building a bag and verifying it refused it differently"
            );

            finalized += 1;
            if waved.is_err() {
                refused += 1;
            }
        }

        // Without these the test could pass having compared nothing that reached the pass,
        // or nothing that failed inside it, which is the half the gate exists for. The
        // seed is fixed and the fixture is captured, so both counts are the same on every
        // machine and are pinned rather than bounded: a corpus that quietly stopped
        // refusing anything would still clear a bound of one.
        assert_eq!(
            finalized, 3_225,
            "the corpus reached a different set of bags"
        );
        assert_eq!(refused, 54, "the finalizing pass refused a different set");
    }

    #[test]
    fn a_wave_wide_enough_to_split_reports_the_lowest_failure() {
        // The parity above runs on a 45-cell proof, whose waves are far too narrow to be
        // handed to a second thread. This is the same comparison at a width that is not:
        // one wave holding the whole bag, failing at three cells for two different
        // reasons, so which cell the reported failure came from is legible.
        const WIDE: usize = CELLS_PER_WORKER * 4;

        let plan = plan_for(&one_wave_bag(WIDE, &[], &[]));
        assert_eq!(
            plan.iter().count(),
            1,
            "cells with no references are one wave"
        );
        assert_eq!(
            plan.iter().next().map(<[usize]>::len),
            Some(WIDE),
            "and that wave holds the whole bag"
        );

        for (by_level, by_hash, expected, ordering) in [
            (
                vec![3usize],
                vec![WIDE / 2, WIDE - 1],
                BY_LEVEL,
                "lowest is the level fault",
            ),
            (
                vec![WIDE / 2, WIDE - 1],
                vec![3usize],
                BY_HASH,
                "lowest is the hash fault",
            ),
        ] {
            let prepared = prepare(&one_wave_bag(WIDE, &by_level, &by_hash))
                .expect("the bag reaches the pass that finalizes cells");
            let (waved, one_pass) = prepared.built_both_ways();
            assert_eq!(waved, Err(expected), "{ordering}");
            assert_eq!(waved, one_pass, "the two plans reported different failures");
        }
    }

    #[test]
    fn a_split_wave_carries_its_cells_to_the_waves_above_it() {
        // The bag above is flat, so nothing there reads what a split wave produced. This
        // one is a fan whose leaves fill a wave wide enough to split while the forks above
        // them are built from what that wave left behind, and it is corrupted rather than
        // read clean: a level bit set in a cell descriptor is a fault the finalizing pass
        // finds, and every ancestor of that cell is then a cell the pass declines to
        // judge.
        let clean = fan_bag(FAN_DEEP);
        let widest = plan_for(&clean)
            .iter()
            .map(<[usize]>::len)
            .max()
            .expect("the fan has waves");
        // Stated as a width rather than as a worker count. What the dispatch does with it
        // is the machine's to decide and a test cannot pin it on every machine, but that
        // the fan offers it four full shares to decide over is a property of the fixture
        // and holds anywhere, so a fan that quietly stopped being wide enough to split is
        // caught here rather than passing as a wave nobody split.
        assert_eq!(
            widest / CELLS_PER_WORKER,
            4,
            "the leaves of this fan are four workers' shares, so nothing but the machine \
             holds the dispatch back here"
        );

        let mut compared = 0usize;
        let mut refused = 0usize;
        for at in (0..clean.len()).step_by(1009) {
            let mut bytes = clean.clone();
            // Bit five of a descriptor byte is the low bit of a cell's level mask, so this
            // lands a fault on a cell wherever it lands on one of those.
            bytes[at] ^= 0x20;
            let Some(prepared) = prepare(&bytes) else {
                continue;
            };
            let (waved, one_pass) = prepared.built_both_ways();
            assert_eq!(
                waved, one_pass,
                "the plan a fan was finalized under reached a caller"
            );
            compared += 1;
            if waved == Err(BY_LEVEL) {
                refused += 1;
            }
        }

        assert!(compared > 0, "no flip reached the finalizing pass");
        assert!(refused > 0, "no flip landed on a cell descriptor");

        // The bag read clean is the floor under the comparison above rather than the gate:
        // a bag with no failing cell agrees under every rule for choosing which failure to
        // report. What it does settle is that a split wave produced the same cells.
        let prepared = prepare(&clean).expect("the fan reaches the finalizing pass");
        let (waved, one_pass) = prepared.built_both_ways();
        assert_eq!(waved, one_pass, "the two plans built different graphs");
        assert_eq!(
            waved.expect("the fan builds"),
            parse_boc(&clean).expect("the fan parses"),
            "the read path built something its own plan does not agree with"
        );
    }

    /// What the machine reports, read here rather than through [`parallelism`].
    ///
    /// An expectation written in terms of the same call the code under test makes holds
    /// however that call answers, so a dispatch that stopped asking the machine at all
    /// would satisfy it. This asks the standard library directly, which leaves the two
    /// readings free to disagree and the assertion able to say so.
    #[cfg(feature = "parallel")]
    fn machine_threads() -> usize {
        std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
    }

    /// How many cells each worker was handed, smallest share first.
    ///
    /// The outcomes carry the thread that produced them, so the shares are counted from
    /// what the workers report rather than from a second copy of the arithmetic that cut
    /// them.
    #[cfg(feature = "parallel")]
    fn shares_of(produced: &WaveOutcomes<std::thread::ThreadId>) -> Vec<usize> {
        let mut counted: Vec<(std::thread::ThreadId, usize)> = Vec::new();
        for (_, outcome) in produced {
            let ran_on = outcome
                .as_ref()
                .ok()
                .and_then(|held| *held)
                .expect("a worker reports the thread it ran on");
            match counted.iter_mut().find(|(id, _)| *id == ran_on) {
                Some((_, share)) => *share += 1,
                None => counted.push((ran_on, 1)),
            }
        }
        let mut shares: Vec<usize> = counted.into_iter().map(|(_, share)| share).collect();
        shares.sort_unstable();
        shares
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn a_wave_is_split_only_where_each_worker_gets_a_full_share() {
        /// Four workers' worth of cells and one over, a width four workers do not divide.
        const UNEVEN: usize = CELLS_PER_WORKER * 4 + 1;

        // What the width gate answers, against what the machine reports rather than
        // against what the dispatch made of it.
        let machine = machine_threads();
        assert_eq!(workers_for(0), 1, "an empty wave stays here");
        assert_eq!(
            workers_for(CELLS_PER_WORKER * 2 - 1),
            1,
            "and one a share short"
        );
        assert_eq!(
            workers_for(CELLS_PER_WORKER * 4),
            machine.min(4),
            "four workers' worth is split as far as the machine goes, up to four"
        );

        // A width the worker count does not divide, which is where the gate's own wording
        // has to be exact. Four workers' worth and one cell over is still four workers'
        // worth, and the shares cut from it are not four full ones: three take a cell more
        // than an even quarter and the fourth takes what is left, which is under a full
        // share. The count of workers is what the width affords; the size of a share is
        // what the cutting leaves.
        assert_eq!(
            workers_for(UNEVEN),
            machine.min(4),
            "a cell over four shares is still four workers' worth"
        );

        // The shares as the workers were actually handed them. Four is passed rather than
        // asked for, so this holds whatever the machine reports.
        let wave: Vec<usize> = (0..UNEVEN).collect();
        let held: Vec<Option<std::thread::ThreadId>> = vec![None; UNEVEN];
        let running_on =
            |_: usize, _: &[Option<std::thread::ThreadId>]| Ok(Some(std::thread::current().id()));
        let produced =
            split_across_workers(&wave, &held, &running_on, 4).expect("four workers is a split");
        let shares = shares_of(&produced);
        assert_eq!(
            shares,
            vec![1022, 1025, 1025, 1025],
            "the shares four workers cut a width of four shares and one cell into"
        );
        assert!(
            shares
                .first()
                .is_some_and(|&least| least < CELLS_PER_WORKER),
            "so a worker is handed less than a full share where the width does not divide"
        );
        assert!(
            shares
                .last()
                .zip(shares.first())
                .is_some_and(|(most, least)| most - least < 4),
            "and the shares differ by fewer cells than there are workers"
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn a_wave_handed_two_workers_is_run_across_both_of_them() {
        // Whether the dispatch splits at all, which is a thing the width gate cannot say
        // on its own: a machine reporting one thread answers one worker for every width,
        // and a gate stated in those terms agrees with a dispatch that never splits. The
        // worker count is passed here rather than asked for, so what is left is the split.
        let wave: Vec<usize> = (0..CELLS_PER_WORKER * 2).collect();
        let held: Vec<Option<usize>> = vec![None; wave.len()];
        let one = |index: usize, _: &[Option<usize>]| Ok(Some(index));

        let empty: [usize; 0] = [];
        assert!(
            split_across_workers(&empty, &held, &one, 2).is_none(),
            "a wave with no cells has no share to hand out"
        );
        assert!(
            split_across_workers(&wave, &held, &one, 1).is_none(),
            "one worker is this thread"
        );

        let produced = split_across_workers(&wave, &held, &one, 2).expect("two workers is a split");
        let mut ran: Vec<usize> = produced.iter().map(|&(index, _)| index).collect();
        ran.sort_unstable();
        assert_eq!(ran, wave, "a split ran every cell of the wave once");
        for (index, outcome) in &produced {
            assert_eq!(
                outcome.as_ref().ok().and_then(|held| *held),
                Some(*index),
                "a worker produced a value for a cell other than the one it was given"
            );
        }

        // And handed to two workers rather than to one that took the wave whole, which is
        // a split the assertions above would not tell from no split at all.
        let unheld: Vec<Option<std::thread::ThreadId>> = vec![None; wave.len()];
        let running_on =
            |_: usize, _: &[Option<std::thread::ThreadId>]| Ok(Some(std::thread::current().id()));
        let across =
            split_across_workers(&wave, &unheld, &running_on, 2).expect("two workers is a split");
        assert_eq!(
            shares_of(&across),
            vec![CELLS_PER_WORKER, CELLS_PER_WORKER],
            "two workers took an even half of the wave each"
        );
    }

    #[test]
    fn the_shape_of_a_bag_decides_how_wide_its_waves_are() {
        // The claim the width gate rests on, counted rather than timed: NET-ADR-012 holds
        // a performance claim in this crate to a count, and this is the count. A path and
        // a fan go through one planner with nothing in it that asks which they are.
        const LINKS: usize = 512;

        let path = plan_for(&path_bag(LINKS));
        assert_eq!(
            path.iter().count(),
            LINKS + 1,
            "a path of n cells finalizes in n waves"
        );
        assert_eq!(
            path.iter().filter(|wave| wave.len() > 1).count(),
            0,
            "and no wave of it holds more than one cell"
        );
        // And what that comes to when the plan is run: every cell of the path is finalized
        // on the thread that asked for it. Watched rather than derived, and derived from
        // the machine least of all, so it says the same thing on a machine reporting one
        // thread as on one reporting many. What keeps a path here is the width of its
        // waves, so a dispatch that stopped reading the width would hand these waves out
        // and be caught here.
        let here = std::thread::current().id();
        let (ran_on, lowest) = finalize(LINKS + 1, &path, &|_: usize, _: &[Option<_>]| {
            Ok(Some(std::thread::current().id()))
        });
        assert!(
            lowest.into_result().is_ok(),
            "the path finalizes without a failure"
        );
        assert!(
            ran_on.iter().all(|held| *held == Some(here)),
            "a wave of a path was handed to a thread other than the caller's"
        );

        let fan = plan_for(&fan_bag(FAN_DEEP));
        let cells: usize = fan.iter().map(<[usize]>::len).sum();
        assert_eq!(
            cells,
            (0..=FAN_DEEP).map(|k| MAX_REFS.pow(k)).sum::<usize>()
        );
        assert_eq!(
            fan.iter().count(),
            FAN_DEEP as usize + 1,
            "a four-way fan of the same cell count finalizes in a handful of waves"
        );
        let widest = fan
            .iter()
            .map(<[usize]>::len)
            .max()
            .expect("the fan has waves");
        assert_eq!(
            widest,
            MAX_REFS.pow(FAN_DEEP),
            "the widest wave is the leaves"
        );
        assert!(
            widest * 4 > cells * 3,
            "which is more than three quarters of the bag in one wave"
        );
    }
}
