use std::collections::BTreeSet;

use crate::error::BridgeResult;

use super::patch::{
    FilePatchOperation, MAX_PATCH_BODY_LINES, MAX_PATCH_BYTES, MAX_PATCH_FILES, MAX_PATCH_HUNKS,
    PatchedFile, invalid_patch, patch_too_large, validate_absolute_patch_path, write_conflict,
};

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ADD_FILE: &str = "*** Add File: ";
const UPDATE_FILE: &str = "*** Update File: ";
const DELETE_FILE: &str = "*** Delete File: ";
const MOVE_TO: &str = "*** Move to: ";
const END_OF_FILE: &str = "*** End of File";
const MAX_CODEX_RECORDS: usize = MAX_PATCH_BODY_LINES + (2 * MAX_PATCH_HUNKS) + MAX_PATCH_FILES + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexFilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub add_bytes: Option<Vec<u8>>,
    pub chunks: Vec<CodexUpdateChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexUpdateChunk {
    pub context: Option<String>,
    pub old_lines: Vec<String>,
    pub new_lines: Vec<String>,
    pub end_of_file: bool,
}

pub(super) fn parse_codex_patch(input: &str) -> BridgeResult<Vec<CodexFilePatch>> {
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
        return Err(invalid_patch("Codex patch begin marker is missing"));
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
    while index < end {
        if patches.len() == MAX_PATCH_FILES {
            return Err(patch_too_large("patch contains too many files"));
        }
        let record = records[index];
        if record.starts_with(MOVE_TO) {
            return Err(invalid_patch("Codex patch move is unsupported"));
        }
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
                    operation,
                    add_bytes: Some(bytes),
                    chunks: Vec::new(),
                }
            }
            FilePatchOperation::Delete => CodexFilePatch {
                path: path.to_owned(),
                operation,
                add_bytes: None,
                chunks: Vec::new(),
            },
            FilePatchOperation::Update => {
                if index < end && records[index].starts_with(MOVE_TO) {
                    return Err(invalid_patch("Codex patch move is unsupported"));
                }
                let mut chunks = Vec::new();
                while index < end && !is_file_directive(records[index]) {
                    if records[index].starts_with(MOVE_TO) {
                        return Err(invalid_patch("Codex patch move is unsupported"));
                    }
                    increment_hunks(&mut total_hunks)?;
                    let (chunk, next) =
                        parse_update_chunk(&records, index, end, &mut total_body_lines)?;
                    chunks.push(chunk);
                    index = next;
                }
                if chunks.is_empty() {
                    return Err(invalid_patch("Codex update-file section is empty"));
                }
                CodexFilePatch {
                    path: path.to_owned(),
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
    let mut changed = false;
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
                old_lines.push(text.to_owned());
                new_lines.push(text.to_owned());
            }
            b'-' => {
                old_lines.push(text.to_owned());
                changed = true;
            }
            b'+' => {
                new_lines.push(text.to_owned());
                changed = true;
            }
            _ => return Err(invalid_patch("Codex update-file line is invalid")),
        }
        increment_body_lines(total_body_lines)?;
        index += 1;
    }
    if !changed {
        return Err(invalid_patch("Codex update chunk has no changes"));
    }
    if end_of_file && index < end {
        if records[index].starts_with(MOVE_TO) {
            return Err(invalid_patch("Codex patch move is unsupported"));
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
    if record.starts_with("--- ") || record.starts_with("+++ ") {
        return Err(invalid_patch("Codex patch contains unified diff syntax"));
    }
    if record.starts_with("*** ") {
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
            let found = find_sequence(&lines, context, cursor, false)
                .ok_or_else(|| write_conflict("Codex patch context was not found"))?;
            cursor = found + 1;
        }
        let start = find_sequence(&lines, &chunk.old_lines, cursor, chunk.end_of_file)
            .ok_or_else(|| write_conflict("Codex patch expected lines were not found"))?;
        replacements.push((start, chunk.old_lines.len(), &chunk.new_lines));
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
        for line in new_lines {
            extend_line(&mut output, line, maximum_output_bytes)?;
        }
        copied = start
            .checked_add(old_len)
            .ok_or_else(|| patch_too_large("patch line position overflowed"))?;
    }
    for line in &lines[copied..] {
        extend_line(&mut output, line, maximum_output_bytes)?;
    }
    if output.as_slice() == base {
        return Err(write_conflict(
            "patch update would leave the file unchanged",
        ));
    }
    Ok(PatchedFile::Write(output))
}

fn find_sequence(
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
    if end_of_file {
        return sequence_matches(haystack, needle, last).then_some(last);
    }
    (start..=last).find(|&candidate| sequence_matches(haystack, needle, candidate))
}

fn sequence_matches(haystack: &[&str], needle: &[String], start: usize) -> bool {
    haystack[start..start + needle.len()]
        .iter()
        .zip(needle)
        .all(|(actual, expected)| *actual == expected)
}
