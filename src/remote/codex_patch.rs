use std::collections::BTreeSet;

use crate::error::BridgeResult;

use super::patch::{
    FilePatchOperation, MAX_PATCH_BODY_LINES, MAX_PATCH_BYTES, MAX_PATCH_FILES, MAX_PATCH_HUNKS,
    PatchedFile, invalid_patch, patch_too_large, validate_absolute_patch_path, write_conflict,
};

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ENVIRONMENT_ID: &str = "*** Environment ID: ";
const ADD_FILE: &str = "*** Add File: ";
const UPDATE_FILE: &str = "*** Update File: ";
const DELETE_FILE: &str = "*** Delete File: ";
const MOVE_TO: &str = "*** Move to: ";
const END_OF_FILE: &str = "*** End of File";
const MAX_CODEX_RECORDS: usize = MAX_PATCH_BODY_LINES + (2 * MAX_PATCH_HUNKS) + MAX_PATCH_FILES + 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexFilePatch {
    pub path: String,
    pub move_path: Option<String>,
    pub operation: FilePatchOperation,
    pub add_bytes: Option<Vec<u8>>,
    pub chunks: Vec<CodexUpdateChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexUpdateChunk {
    pub context: Option<String>,
    pub old_lines: Vec<String>,
    pub new_lines: Vec<String>,
    pub context_line_indices: Vec<(usize, usize)>,
    pub end_of_file: bool,
}

pub(super) fn parse_codex_patch(
    input: &str,
    expected_environment_id: &str,
) -> BridgeResult<Vec<CodexFilePatch>> {
    if input.len() > MAX_PATCH_BYTES {
        return Err(patch_too_large("patch exceeds the compiled byte limit"));
    }
    if input.as_bytes().contains(&0) {
        return Err(invalid_patch("patch contains NUL"));
    }

    let input = input.trim_matches('\n');
    let records = input
        .split('\n')
        .take(MAX_CODEX_RECORDS + 1)
        .collect::<Vec<_>>();
    if records.len() > MAX_CODEX_RECORDS {
        return Err(patch_too_large("Codex patch contains too many records"));
    }
    if records.first().copied() != Some(BEGIN_PATCH) {
        return Err(invalid_patch("patch must use Codex apply_patch syntax"));
    }
    let end = records
        .iter()
        .position(|record| *record == END_PATCH)
        .ok_or_else(|| invalid_patch("Codex patch end marker is missing"))?;
    if end + 1 != records.len() {
        return Err(invalid_patch("Codex patch envelope has trailing data"));
    }

    let mut patches = Vec::new();
    let mut paths = BTreeSet::new();
    let mut total_hunks = 0usize;
    let mut total_body_lines = 0usize;
    let mut index = 1usize;
    if index < end
        && let Some(environment_id) = records[index].strip_prefix(ENVIRONMENT_ID)
    {
        if environment_id.is_empty() {
            return Err(invalid_patch("Codex patch environment id is empty"));
        }
        if environment_id != expected_environment_id {
            return Err(invalid_patch(
                "Codex patch environment id does not match host",
            ));
        }
        index += 1;
    }
    while index < end {
        if patches.len() == MAX_PATCH_FILES {
            return Err(patch_too_large("patch contains too many files"));
        }
        let record = records[index];
        let (operation, path) = if let Some(path) = record.strip_prefix(ADD_FILE) {
            (FilePatchOperation::Create, path)
        } else if let Some(path) = record.strip_prefix(UPDATE_FILE) {
            (FilePatchOperation::Update, path)
        } else if let Some(path) = record.strip_prefix(DELETE_FILE) {
            (FilePatchOperation::Delete, path)
        } else {
            return Err(invalid_patch("Codex patch file directive is invalid"));
        };
        validate_codex_path(path)?;
        if !paths.insert(path.to_owned()) {
            return Err(invalid_patch("patch contains a duplicate path"));
        }
        index += 1;

        let patch = match operation {
            FilePatchOperation::Create => {
                let mut bytes = Vec::new();
                while index < end && !is_file_directive(records[index]) {
                    let record = records[index];
                    reject_nested_or_mixed_record(record)?;
                    let text = record
                        .strip_prefix('+')
                        .ok_or_else(|| invalid_patch("Codex add-file line is invalid"))?;
                    increment_body_lines(&mut total_body_lines)?;
                    extend_line(&mut bytes, text, MAX_PATCH_BYTES)?;
                    index += 1;
                }
                if bytes.is_empty() {
                    return Err(invalid_patch("Codex add-file section is empty"));
                }
                CodexFilePatch {
                    path: path.to_owned(),
                    move_path: None,
                    operation,
                    add_bytes: Some(bytes),
                    chunks: Vec::new(),
                }
            }
            FilePatchOperation::Delete => CodexFilePatch {
                path: path.to_owned(),
                move_path: None,
                operation,
                add_bytes: None,
                chunks: Vec::new(),
            },
            FilePatchOperation::Update => {
                let move_path = if index < end {
                    records[index]
                        .strip_prefix(MOVE_TO)
                        .map(|move_path| {
                            validate_codex_path(move_path)?;
                            if move_path != path && !paths.insert(move_path.to_owned()) {
                                return Err(invalid_patch("patch contains an overlapping path"));
                            }
                            index += 1;
                            Ok(move_path.to_owned())
                        })
                        .transpose()?
                } else {
                    None
                };
                let mut chunks = Vec::new();
                while index < end && !is_file_directive(records[index]) {
                    if records[index].starts_with(MOVE_TO) {
                        return Err(invalid_patch("Codex patch move directive is misplaced"));
                    }
                    increment_hunks(&mut total_hunks)?;
                    let (chunk, next) =
                        parse_update_chunk(&records, index, end, &mut total_body_lines)?;
                    chunks.push(chunk);
                    index = next;
                }
                CodexFilePatch {
                    path: path.to_owned(),
                    move_path,
                    operation,
                    add_bytes: None,
                    chunks,
                }
            }
        };
        patches.push(patch);
    }

    if patches.is_empty() {
        return Err(invalid_patch("Codex patch contains no file operations"));
    }
    Ok(patches)
}

fn parse_update_chunk(
    records: &[&str],
    start: usize,
    end: usize,
    total_body_lines: &mut usize,
) -> BridgeResult<(CodexUpdateChunk, usize)> {
    let mut index = start;
    let context = if records[index] == "@@" {
        index += 1;
        None
    } else if let Some(context) = records[index].strip_prefix("@@ ") {
        if context.is_empty() {
            return Err(invalid_patch("Codex patch context is empty"));
        }
        index += 1;
        Some(context.to_owned())
    } else {
        None
    };

    let mut old_lines = Vec::new();
    let mut new_lines = Vec::new();
    let mut context_line_indices = Vec::new();
    let mut end_of_file = false;
    while index < end {
        let record = records[index];
        if record == END_OF_FILE {
            end_of_file = true;
            index += 1;
            while index < end && records[index].is_empty() {
                index += 1;
            }
            break;
        }
        if record == "@@"
            || record.starts_with("@@ ")
            || is_file_directive(record)
            || record.starts_with(MOVE_TO)
        {
            break;
        }
        reject_nested_or_mixed_record(record)?;
        let (prefix, text) = record
            .split_at_checked(1)
            .ok_or_else(|| invalid_patch("Codex update-file line is invalid"))?;
        match prefix.as_bytes()[0] {
            b' ' => {
                context_line_indices.push((old_lines.len(), new_lines.len()));
                old_lines.push(text.to_owned());
                new_lines.push(text.to_owned());
            }
            b'-' => {
                old_lines.push(text.to_owned());
            }
            b'+' => {
                new_lines.push(text.to_owned());
            }
            _ => return Err(invalid_patch("Codex update-file line is invalid")),
        }
        increment_body_lines(total_body_lines)?;
        index += 1;
    }
    if end_of_file && index < end {
        if records[index].starts_with(MOVE_TO) {
            return Err(invalid_patch("Codex patch move directive is misplaced"));
        }
        if !is_file_directive(records[index]) {
            return Err(invalid_patch("Codex end-of-file marker is not final"));
        }
    }
    Ok((
        CodexUpdateChunk {
            context,
            old_lines,
            new_lines,
            context_line_indices,
            end_of_file,
        },
        index,
    ))
}

fn validate_codex_path(path: &str) -> BridgeResult<()> {
    if !path.starts_with('/') {
        return Err(invalid_patch("Codex patch path is not absolute"));
    }
    if path.contains(['\t', '\r', '\n']) {
        return Err(invalid_patch("Codex patch path is invalid"));
    }
    validate_absolute_patch_path(path)
}

fn is_file_directive(record: &str) -> bool {
    record.starts_with(ADD_FILE)
        || record.starts_with(UPDATE_FILE)
        || record.starts_with(DELETE_FILE)
}

fn reject_nested_or_mixed_record(record: &str) -> BridgeResult<()> {
    if record == BEGIN_PATCH || record == END_PATCH {
        return Err(invalid_patch("Codex patch envelope is nested"));
    }
    if record.starts_with(ENVIRONMENT_ID) || record.starts_with("*** ") {
        return Err(invalid_patch("Codex patch marker is invalid"));
    }
    Ok(())
}

fn increment_hunks(total: &mut usize) -> BridgeResult<()> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| patch_too_large("patch hunk count overflowed"))?;
    if *total > MAX_PATCH_HUNKS {
        return Err(patch_too_large("patch contains too many hunks"));
    }
    Ok(())
}

fn increment_body_lines(total: &mut usize) -> BridgeResult<()> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| patch_too_large("patch body count overflowed"))?;
    if *total > MAX_PATCH_BODY_LINES {
        return Err(patch_too_large("patch contains too many body lines"));
    }
    Ok(())
}

fn extend_line(bytes: &mut Vec<u8>, line: &str, maximum: usize) -> BridgeResult<()> {
    let next = bytes
        .len()
        .checked_add(line.len())
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| patch_too_large("patched file size overflowed"))?;
    if next > maximum {
        return Err(patch_too_large("patched file exceeds the output limit"));
    }
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    Ok(())
}

pub(super) fn apply_codex_file(
    base: Option<&[u8]>,
    patch: &CodexFilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile> {
    match patch.operation {
        FilePatchOperation::Create => {
            if base.is_some() {
                return Err(write_conflict(
                    "patch base presence does not match operation",
                ));
            }
            let bytes = patch
                .add_bytes
                .as_ref()
                .ok_or_else(|| invalid_patch("Codex add-file content is missing"))?;
            if bytes.len() > maximum_output_bytes {
                return Err(patch_too_large("patched file exceeds the output limit"));
            }
            Ok(PatchedFile::Write(bytes.clone()))
        }
        FilePatchOperation::Delete => {
            if base.is_none() {
                return Err(write_conflict(
                    "patch base presence does not match operation",
                ));
            }
            Ok(PatchedFile::Delete)
        }
        FilePatchOperation::Update => {
            let base =
                base.ok_or_else(|| write_conflict("patch base presence does not match operation"))?;
            apply_update(base, patch, maximum_output_bytes)
        }
    }
}

fn apply_update(
    base: &[u8],
    patch: &CodexFilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile> {
    if base.contains(&0) {
        return Err(invalid_patch("patch base contains NUL"));
    }
    let base_text =
        std::str::from_utf8(base).map_err(|_| invalid_patch("patch base is not UTF-8"))?;
    let mut lines = base_text.split('\n').collect::<Vec<_>>();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }

    let mut replacements = Vec::with_capacity(patch.chunks.len());
    let mut cursor = 0usize;
    for chunk in &patch.chunks {
        if let Some(context) = &chunk.context {
            let context = std::slice::from_ref(context);
            let found = seek_sequence(&lines, context, cursor, false)
                .ok_or_else(|| write_conflict("Codex patch context was not found"))?;
            cursor = found + 1;
        }
        if chunk.old_lines.is_empty() && chunk.new_lines.is_empty() {
            continue;
        }
        let start = if chunk.old_lines.is_empty() && chunk.context.is_none() {
            lines.len()
        } else {
            seek_sequence(&lines, &chunk.old_lines, cursor, chunk.end_of_file)
                .ok_or_else(|| write_conflict("Codex patch expected lines were not found"))?;
        };
        let mut new_lines = chunk.new_lines.clone();
        for (old_index, new_index) in &chunk.context_line_indices {
            let actual = lines
                .get(start + old_index)
                .ok_or_else(|| write_conflict("Codex patch context was not found"))?;
            new_lines[*new_index] = (*actual).to_owned();
        }
        replacements.push((start, chunk.old_lines.len(), new_lines));
        cursor = start
            .checked_add(chunk.old_lines.len())
            .ok_or_else(|| patch_too_large("patch line position overflowed"))?;
    }

    let mut output = Vec::with_capacity(base.len().min(maximum_output_bytes));
    let mut copied = 0usize;
    for (start, old_len, new_lines) in replacements {
        for line in &lines[copied..start] {
            extend_line(&mut output, line, maximum_output_bytes)?;
        }
        for line in &new_lines {
            extend_line(&mut output, line, maximum_output_bytes)?;
        }
        copied = start
            .checked_add(old_len)
            .ok_or_else(|| patch_too_large("patch line position overflowed"))?;
    }
    for line in &lines[copied..] {
        extend_line(&mut output, line, maximum_output_bytes)?;
    }
    if output.as_slice() == base && patch.move_path.is_none() {
        return Err(write_conflict(
            "patch update would leave the file unchanged",
        ));
    }
    Ok(PatchedFile::Write(output))
}

fn seek_sequence(
    haystack: &[&str],
    needle: &[String],
    start: usize,
    end_of_file: bool,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(if end_of_file {
            haystack.len()
        } else {
            start.min(haystack.len())
        });
    }
    let last = haystack.len().checked_sub(needle.len())?;
    if start > last {
        return None;
    }
    if end_of_file && let Some(found) = seek_candidates(haystack, needle, last..=last) {
        return Some(found);
    }
    seek_candidates(haystack, needle, start..=last)
}

fn seek_candidates(
    haystack: &[&str],
    needle: &[String],
    candidates: std::ops::RangeInclusive<usize>,
) -> Option<usize> {
    for mode in [
        MatchMode::Exact,
        MatchMode::TrimEnd,
        MatchMode::Trim,
        MatchMode::UnicodeNormalized,
    ] {
        for candidate in candidates.clone() {
            if sequence_matches(haystack, needle, candidate, mode) {
                return Some(candidate);
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
enum MatchMode {
    Exact,
    TrimEnd,
    Trim,
    UnicodeNormalized,
}

fn sequence_matches(haystack: &[&str], needle: &[String], start: usize, mode: MatchMode) -> bool {
    haystack[start..start + needle.len()]
        .iter()
        .zip(needle)
        .all(|(actual, expected)| match mode {
            MatchMode::Exact => *actual == expected,
            MatchMode::TrimEnd => actual.trim_end() == expected.trim_end(),
            MatchMode::Trim => actual.trim() == expected.trim(),
            MatchMode::UnicodeNormalized => {
                normalize_unicode(actual) == normalize_unicode(expected)
            }
        })
}

fn normalize_unicode(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| match character {
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
            | '\u{2212}' => '-',
            '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => '\'',
            '\u{201c}' | '\u{201d}' | '\u{201e}' | '\u{201f}' => '"',
            '\u{00a0}' | '\u{2002}' | '\u{2003}' | '\u{2004}' | '\u{2005}' | '\u{2006}'
            | '\u{2007}' | '\u{2008}' | '\u{2009}' | '\u{200a}' | '\u{202f}' | '\u{205f}'
            | '\u{3000}' => ' ',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // UPSTREAM_APPLY_PATCH_BASELINE: 422239eb4b1e0d0f85fac7256a079a1befe78472
    // Fixtures track codex-rs/apply-patch/src/{parser,streaming_parser,seek_sequence}.rs.

    fn apply(base: &[u8], patch: &str) -> crate::BridgeResult<super::PatchedFile> {
        let parsed = super::parse_codex_patch(patch, "dev")?;
        assert_eq!(parsed.len(), 1);
        super::apply_codex_file(Some(base), &parsed[0], super::MAX_PATCH_BYTES)
    }

    #[test]
    fn repeated_context_selectors_advance_before_one_change() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/src/lib.rs\n",
            "@@ impl Server\n",
            "@@ fn dispatch\n",
            "-old();\n",
            "+new();\n",
            "*** End Patch\n",
        );

        assert_eq!(
            apply(b"impl Server\nfn other() {}\nfn dispatch\nold();\n", patch,).unwrap(),
            super::PatchedFile::Write(
                b"impl Server\nfn other() {}\nfn dispatch\nnew();\n".to_vec(),
            ),
        );
    }

    #[test]
    fn native_context_matching_uses_ordered_fallbacks() {
        for (base, context) in [
            ("target   \nold\n", "target"),
            ("  target  \nold\n", "target"),
            ("“target”\nold\n", "\"target\""),
        ] {
            let patch = format!(
                "*** Begin Patch\n*** Update File: /srv/repo/a\n@@ {context}\n-old\n+new\n*** End Patch\n"
            );
            let expected = base.replace("old\n", "new\n").into_bytes();
            assert_eq!(
                apply(base.as_bytes(), &patch).unwrap(),
                super::PatchedFile::Write(expected),
                "context {context:?}",
            );
        }
    }

    #[test]
    fn native_environment_preamble_and_move_directive_parse() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Environment ID: dev\n",
            "*** Update File: /srv/repo/a\n",
            "*** Move to: /srv/repo/b\n",
            "*** End Patch\n",
        );

        let parsed = super::parse_codex_patch(patch, "dev").unwrap();
        assert_eq!(parsed[0].path, "/srv/repo/a");
        assert_eq!(parsed[0].move_path.as_deref(), Some("/srv/repo/b"));

        assert_eq!(
            super::parse_codex_patch(patch, "prod").unwrap_err().message,
            "Codex patch environment id does not match host",
        );
    }
}
