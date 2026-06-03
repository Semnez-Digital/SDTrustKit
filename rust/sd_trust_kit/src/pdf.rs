use crate::asn1;
use flate2::read::ZlibDecoder;
use md5::{Digest as Md5Digest, Md5};
use std::io::Read;
use std::ops::Range;

const PDF_PASSWORD_PADDING: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigDict {
    pub object_number: Option<usize>,
    pub object_generation: Option<usize>,
    pub object_start: usize,
    pub byte_range: Vec<usize>,
    pub cms_bytes: Vec<u8>,
    pub cms_hex_length: usize,
    pub contents_placeholder_range: Range<usize>,
    pub modification_date: Option<String>,
    pub type_name: Option<String>,
    pub sub_filter: Option<String>,
    pub usage_rights: bool,
}

impl SigDict {
    fn object_id(&self) -> Option<PDFObjectId> {
        Some(PDFObjectId {
            number: self.object_number?,
            generation: self.object_generation?,
        })
    }

    pub fn signed_revision_size(&self) -> usize {
        if self.byte_range.len() == 4 {
            self.byte_range[2].saturating_add(self.byte_range[3])
        } else {
            0
        }
    }

    pub fn is_document_timestamp(&self) -> bool {
        self.type_name.as_deref() == Some("DocTimeStamp")
            || self.sub_filter.as_deref() == Some("ETSI.RFC3161")
    }

    pub fn is_usage_rights_signature(&self) -> bool {
        self.usage_rights
    }

    pub fn byte_range_gap_matches_contents(&self) -> bool {
        if self.byte_range.len() != 4 {
            return false;
        }
        let gap_start = self.byte_range[0].saturating_add(self.byte_range[1]);
        gap_start == self.contents_placeholder_range.start
            && self.byte_range[2] == self.contents_placeholder_range.end
            && self.contents_placeholder_range.len() == self.cms_hex_length + 2
    }

    pub fn parse_all(pdf: &[u8]) -> Vec<Self> {
        let out = Self::parse_all_including_duplicates(pdf);
        let mut seen = Vec::<(Vec<usize>, Vec<u8>)>::new();
        out.into_iter()
            .filter(|sig| {
                if seen
                    .iter()
                    .any(|(br, cms)| br == &sig.byte_range && cms == &sig.cms_bytes)
                {
                    false
                } else {
                    seen.push((sig.byte_range.clone(), sig.cms_bytes.clone()));
                    true
                }
            })
            .collect()
    }

    fn parse_all_including_duplicates(pdf: &[u8]) -> Vec<Self> {
        let mut out = Vec::new();
        let mut search_from = 0usize;
        let needle = b"/ByteRange";
        let direct_streams = direct_stream_ranges(pdf);
        let scan_until = final_eof_end(pdf).unwrap_or(pdf.len());
        while let Some(br_range) = first_range(needle, pdf, search_from, Some(scan_until)) {
            search_from = br_range.end;
            if direct_streams
                .iter()
                .any(|range| range.contains(&br_range.start))
                || is_inside_stream(pdf, br_range.start)
            {
                continue;
            }
            if let Some(sig) = parse_one(pdf, br_range) {
                out.push(sig);
            }
        }
        out.sort_by_key(Self::signed_revision_size);
        out
    }

    pub fn contains_unparseable_signature_contents(pdf: &[u8]) -> bool {
        let mut search_from = 0usize;
        let needle = b"/ByteRange";
        let direct_streams = direct_stream_ranges(pdf);
        let scan_until = final_eof_end(pdf).unwrap_or(pdf.len());
        while let Some(br_range) = first_range(needle, pdf, search_from, Some(scan_until)) {
            search_from = br_range.end;
            if direct_streams
                .iter()
                .any(|range| range.contains(&br_range.start))
                || is_inside_stream(pdf, br_range.start)
            {
                continue;
            }
            if parse_one(pdf, br_range.clone()).is_some() {
                continue;
            }
            if is_unparseable_signature_candidate(pdf, br_range) {
                return true;
            }
        }
        false
    }
}

pub fn validated_byte_range(
    br: &[usize],
    file_size: usize,
) -> Option<(Range<usize>, Range<usize>)> {
    if br.len() != 4 {
        return None;
    }
    let (start1, len1, start2, len2) = (br[0], br[1], br[2], br[3]);
    if start1 > file_size || start2 > file_size {
        return None;
    }
    if len1 > file_size.saturating_sub(start1) || len2 > file_size.saturating_sub(start2) {
        return None;
    }
    Some((start1..start1 + len1, start2..start2 + len2))
}

pub fn trailing_bytes_are_pdf_whitespace(pdf: &[u8], offset: usize) -> bool {
    offset <= pdf.len() && pdf[offset..].iter().all(|b| is_whitespace(*b))
}

pub fn looks_like_pdf_document(pdf: &[u8]) -> bool {
    pdf.starts_with(b"%PDF-") && pdf.windows(b"%%EOF".len()).any(|window| window == b"%%EOF")
}

pub fn requires_non_empty_open_password(pdf: &[u8]) -> bool {
    if !looks_like_pdf_document(pdf) {
        return false;
    }
    let Some(params) = standard_encryption_parameters(pdf) else {
        return false;
    };
    !empty_user_password_matches(&params)
}

pub fn has_encryption_dictionary(pdf: &[u8]) -> bool {
    looks_like_pdf_document(pdf) && ascii_outside_streams(pdf).contains("/Encrypt")
}

pub fn has_minimal_page_tree(pdf: &[u8]) -> bool {
    let objects = incremental_objects_with_object_streams(pdf);
    let Some(catalog) = objects
        .iter()
        .rev()
        .find(|object| contains_pdf_name_pair(&object.scan, "Type", "Catalog"))
    else {
        return false;
    };
    let Some(pages_id) = reference_after_name(&catalog.scan, "Pages") else {
        return false;
    };
    objects
        .iter()
        .rev()
        .find(|object| object.id == pages_id)
        .is_some_and(|pages| {
            contains_pdf_name_pair(&pages.scan, "Type", "Pages")
                && contains_pdf_name(&pages.scan, "Kids")
                && contains_pdf_name(&pages.scan, "Count")
        })
}

pub fn later_revision_looks_like_validation_data_only(pdf: &[u8], offset: usize) -> bool {
    if offset >= pdf.len() {
        return false;
    }
    let tail_scan = ascii_outside_streams(&pdf[offset..]);
    if !contains_pdf_name(&tail_scan, "DSS") {
        return false;
    }
    let prior_objects = incremental_objects(&pdf[..offset]);
    let objects = incremental_objects_with_object_streams(&pdf[offset..]);
    if objects.is_empty() {
        return false;
    }
    let mut catalog_objects = Vec::new();
    let mut xref_objects = Vec::new();
    let mut object_streams = Vec::new();
    let mut metadata_objects = Vec::new();
    let mut safe_new_objects = Vec::new();
    let mut allowed_evidence_objects = Vec::new();
    let mut saw_dss_hook = false;

    for object in &objects {
        if contains_pdf_name_pair(&object.scan, "Type", "XRef") {
            xref_objects.push(object.id);
            continue;
        }
        if contains_pdf_name_pair(&object.scan, "Type", "ObjStm") {
            object_streams.push(object.id);
            continue;
        }
        if catalog_update_only_adds_dss(object, &prior_objects) {
            catalog_objects.push(object.id);
            for reference in object_references(&object.scan) {
                push_unique(&mut allowed_evidence_objects, reference);
            }
            saw_dss_hook = true;
            continue;
        }
        if has_disallowed_validation_tail_marker(&object.scan) {
            return false;
        }
        if object_looks_like_document_metadata(&object.scan) {
            metadata_objects.push(object.id);
            continue;
        }
        if !prior_objects.iter().any(|prior| prior.id == object.id) {
            safe_new_objects.push(object.id);
            continue;
        }
        if object_looks_like_dss_dictionary(&object.scan) {
            push_unique(&mut allowed_evidence_objects, object.id);
            saw_dss_hook = true;
        }
    }
    if !saw_dss_hook {
        return false;
    }
    let mut changed = true;
    while changed {
        changed = false;
        for object in &objects {
            if allowed_evidence_objects.contains(&object.id) {
                for reference in object_references(&object.scan) {
                    if !allowed_evidence_objects.contains(&reference) {
                        allowed_evidence_objects.push(reference);
                        changed = true;
                    }
                }
            }
        }
    }
    objects.iter().all(|object| {
        catalog_objects.contains(&object.id)
            || xref_objects.contains(&object.id)
            || object_streams.contains(&object.id)
            || metadata_objects.contains(&object.id)
            || safe_new_objects.contains(&object.id)
            || allowed_evidence_objects.contains(&object.id)
    })
}

pub fn later_validation_data_revision_changes_existing_object(pdf: &[u8], offset: usize) -> bool {
    if offset >= pdf.len() {
        return false;
    }
    let tail_scan = ascii_outside_streams(&pdf[offset..]);
    if !contains_pdf_name(&tail_scan, "DSS") {
        return false;
    }
    if contains_pdf_name(&tail_scan, "VRI") {
        return false;
    }
    let prior_objects = incremental_objects(&pdf[..offset]);
    let tail_objects = incremental_objects(&pdf[offset..]);
    tail_objects.iter().any(|object| {
        !contains_pdf_name_pair(&object.scan, "Type", "XRef")
            && !catalog_update_only_adds_dss(object, &prior_objects)
            && !catalog_update_only_adds_validation_material(object, &prior_objects, &tail_objects)
            && !validation_data_object_update(object, &prior_objects)
            && !object_looks_like_document_metadata(&object.scan)
            && object_changed_from_prior_revision(object, &prior_objects)
    })
}

pub fn signature_dictionary_changed_after_signed_revision(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(id) = sig.object_id() else {
        return false;
    };
    let signed_revision_size = sig.signed_revision_size();
    if signed_revision_size >= pdf.len() {
        return false;
    }

    let Some(signed_revision_object) = latest_object_with_id(&pdf[..signed_revision_size], id)
    else {
        return false;
    };
    let Some(final_object) = latest_object_with_id(pdf, id) else {
        return false;
    };
    if final_object.start < signed_revision_size {
        return false;
    }
    normalized_pdf_object_text(&signed_revision_object.scan)
        != normalized_pdf_object_text(&final_object.scan)
}

pub fn signature_field_reference_changed_after_signed_revision(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let signed_revision_size = sig.signed_revision_size();
    if signed_revision_size >= pdf.len() {
        return false;
    }

    let signed_field_ids =
        signature_field_ids_referencing_signature(&pdf[..signed_revision_size], signature_id);
    if signed_field_ids.is_empty() {
        return false;
    }

    let final_objects = incremental_objects(pdf);
    signed_field_ids.iter().any(|field_id| {
        final_objects
            .iter()
            .rev()
            .find(|object| object.id == *field_id)
            .map(|object| {
                object.start >= signed_revision_size
                    && field_value_reference(&object.scan) != Some(signature_id)
            })
            .unwrap_or(false)
    })
}

pub fn signature_has_duplicate_field_references_in_signed_revision(
    pdf: &[u8],
    sig: &SigDict,
) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let signed_revision_size = sig.signed_revision_size();
    if signed_revision_size > pdf.len() {
        return false;
    }
    signature_field_ids_referencing_signature(&pdf[..signed_revision_size], signature_id).len() > 1
}

pub fn signature_field_tree_has_self_reference(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let objects = latest_revision_objects(pdf);
    signature_field_ids_referencing_signature(pdf, signature_id)
        .into_iter()
        .any(|field_id| {
            objects
                .iter()
                .find(|object| object.id == field_id)
                .map(|object| array_references_after_name(&object.scan, "Kids").contains(&field_id))
                .unwrap_or(false)
        })
}

pub fn signature_dictionary_is_unreferenced_orphan(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let final_fields = acroform_signature_fields(pdf);
    let signed_revision_size = sig.signed_revision_size();
    let signed_fields = if signed_revision_size <= pdf.len() {
        acroform_signature_fields(&pdf[..signed_revision_size])
    } else {
        Vec::new()
    };
    let has_field_model = !final_fields.is_empty() || !signed_fields.is_empty();
    has_field_model
        && sig.object_start >= signed_revision_size
        && !final_fields
            .iter()
            .chain(signed_fields.iter())
            .any(|field| field.value == Some(signature_id))
}

pub fn signature_dictionary_has_field_reference(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let final_fields = acroform_signature_fields(pdf);
    let signed_revision_size = sig.signed_revision_size();
    let signed_fields = if signed_revision_size <= pdf.len() {
        acroform_signature_fields(&pdf[..signed_revision_size])
    } else {
        Vec::new()
    };
    final_fields
        .iter()
        .chain(signed_fields.iter())
        .any(|field| field.value == Some(signature_id))
}

pub fn signature_has_shadow_copy_after_signed_revision(pdf: &[u8], sig: &SigDict) -> bool {
    let Some(signature_id) = sig.object_id() else {
        return false;
    };
    let signed_revision_size = sig.signed_revision_size();
    if signed_revision_size >= pdf.len() {
        return false;
    }
    SigDict::parse_all_including_duplicates(pdf)
        .into_iter()
        .any(|other| {
            other.object_id() != Some(signature_id)
                && other.object_start >= signed_revision_size
                && other.byte_range == sig.byte_range
                && other.cms_bytes == sig.cms_bytes
        })
}

pub fn page_count_changed_after_signed_revision(pdf: &[u8], sig: &SigDict) -> bool {
    let signed_revision_size = sig.signed_revision_size();
    if signed_revision_size >= pdf.len() {
        return false;
    }
    let Some(signed_count) = page_count(&pdf[..signed_revision_size]) else {
        return false;
    };
    let Some(final_count) = page_count(pdf) else {
        return false;
    };
    signed_count != final_count
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PDFObjectId {
    number: usize,
    generation: usize,
}

#[derive(Clone, Debug)]
struct IncrementalObject {
    id: PDFObjectId,
    start: usize,
    scan: String,
}

fn parse_one(bytes: &[u8], br_range: Range<usize>) -> Option<SigDict> {
    let mut i = br_range.end;
    while i < bytes.len() && !is_digit(bytes[i]) && bytes[i] != b'[' {
        i += 1;
    }
    if bytes.get(i) == Some(&b'[') {
        i += 1;
    }
    let mut nums = Vec::new();
    for _ in 0..4 {
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        let (n, next) = parse_usize_digits(bytes, i)?;
        i = next;
        nums.push(n);
    }

    let (object_start, object_end, object_id) = signature_object_bounds(bytes, br_range)?;
    let modification_date = parse_modification_date(bytes, object_start, object_end);
    let type_name = parse_pdf_name_after("/Type", bytes, object_start, object_end);
    let sub_filter = parse_pdf_name_after("/SubFilter", bytes, object_start, object_end);
    if !is_signature_dictionary_candidate(type_name.as_deref(), sub_filter.as_deref()) {
        return None;
    }
    let c_range = first_range(b"/Contents", bytes, object_start, Some(object_end))?;
    let mut j = c_range.end;
    while j < object_end && is_whitespace(bytes[j]) {
        j += 1;
    }
    if j >= object_end || bytes[j] != b'<' {
        return None;
    }
    let hex_start = j + 1;
    let mut k = hex_start;
    while k < object_end && bytes[k] != b'>' {
        k += 1;
    }
    if k >= object_end {
        return None;
    }
    let hex_len = k - hex_start;
    if hex_len % 2 != 0 {
        return None;
    }
    let padded = hex::decode(std::str::from_utf8(&bytes[hex_start..k]).ok()?).ok()?;
    let cms = asn1::normalized_asn1_first_object(&padded)?;
    Some(SigDict {
        object_number: object_id.map(|id| id.number),
        object_generation: object_id.map(|id| id.generation),
        object_start,
        byte_range: nums,
        cms_bytes: cms,
        cms_hex_length: hex_len,
        contents_placeholder_range: j..k + 1,
        modification_date,
        type_name,
        sub_filter,
        usage_rights: is_usage_rights_signature_dictionary(bytes, object_start, object_end),
    })
}

fn direct_stream_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut search_from = 0usize;
    while let Some(start) = first_range(b"stream", bytes, search_from, None) {
        search_from = start.end;
        if start.start >= 3 && &bytes[start.start - 3..start.start] == b"end" {
            continue;
        }
        let Some(length) = direct_length_before_stream(bytes, start.start) else {
            continue;
        };
        let mut content_start = start.end;
        if bytes.get(content_start) == Some(&b'\r') {
            content_start += 1;
        }
        if bytes.get(content_start) == Some(&b'\n') {
            content_start += 1;
        }
        ranges.push(content_start..bytes.len().min(content_start + length));
    }
    ranges
}

fn direct_length_before_stream(bytes: &[u8], stream_start: usize) -> Option<usize> {
    let window_start = stream_start.saturating_sub(1024);
    let length_range = last_range(b"/Length", bytes, stream_start)?;
    if length_range.start < window_start {
        return None;
    }
    let mut i = length_range.end;
    while i < stream_start && is_whitespace(bytes[i]) {
        i += 1;
    }
    let (value, _) = parse_usize_digits(&bytes[..stream_start], i)?;
    Some(value)
}

fn parse_usize_digits(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut i = start;
    let mut value = 0usize;
    let mut any = false;
    while i < bytes.len() && is_digit(bytes[i]) {
        value = value
            .checked_mul(10)?
            .checked_add(usize::from(bytes[i] - b'0'))?;
        i += 1;
        any = true;
    }
    any.then_some((value, i))
}

fn is_inside_stream(bytes: &[u8], index: usize) -> bool {
    let last_end = last_range(b"endstream", bytes, index)
        .map(|range| range.start)
        .unwrap_or(usize::MAX);
    let mut before = index;
    while let Some(start) = last_range(b"stream", bytes, before) {
        if start.start >= 3 && &bytes[start.start - 3..start.start] == b"end" {
            before = start.start;
            continue;
        }
        return last_end == usize::MAX || start.start > last_end;
    }
    false
}

fn is_unparseable_signature_candidate(bytes: &[u8], br_range: Range<usize>) -> bool {
    let Some((object_start, object_end, _)) = signature_object_bounds(bytes, br_range) else {
        return false;
    };
    let type_name = parse_pdf_name_after("/Type", bytes, object_start, object_end);
    let sub_filter = parse_pdf_name_after("/SubFilter", bytes, object_start, object_end);
    is_signature_dictionary_candidate(type_name.as_deref(), sub_filter.as_deref())
        && signature_contents_look_nonempty(bytes, object_start, object_end)
}

fn signature_contents_look_nonempty(bytes: &[u8], object_start: usize, object_end: usize) -> bool {
    let Some(c_range) = first_range(b"/Contents", bytes, object_start, Some(object_end)) else {
        return false;
    };
    let mut i = c_range.end;
    while i < object_end && is_whitespace(bytes[i]) {
        i += 1;
    }
    if bytes.get(i) != Some(&b'<') {
        return true;
    }
    i += 1;
    let mut saw_non_zero = false;
    while i < object_end && bytes[i] != b'>' {
        if !is_whitespace(bytes[i]) && bytes[i] != b'0' {
            saw_non_zero = true;
            break;
        }
        i += 1;
    }
    saw_non_zero
}

struct StandardEncryptionParameters {
    o: Vec<u8>,
    u: Vec<u8>,
    p: i32,
    r: usize,
    key_len: usize,
    id0: Vec<u8>,
    encrypt_metadata: bool,
}

fn standard_encryption_parameters(pdf: &[u8]) -> Option<StandardEncryptionParameters> {
    let dict = standard_encryption_dictionary(pdf)?;
    let r = integer_after_name(&dict, b"R")? as usize;
    let key_len = (last_integer_after_name(&dict, b"Length")
        .unwrap_or(40)
        .max(40) as usize)
        / 8;
    Some(StandardEncryptionParameters {
        o: bytes_after_name(&dict, b"O")?,
        u: bytes_after_name(&dict, b"U")?,
        p: integer_after_name(&dict, b"P")?,
        r,
        key_len,
        id0: first_file_id(pdf)?,
        encrypt_metadata: !name_followed_by_false(&dict, b"EncryptMetadata"),
    })
}

fn standard_encryption_dictionary(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut search_from = 0usize;
    while let Some(filter) = first_range(b"/Filter", pdf, search_from, None) {
        search_from = filter.end;
        let object_start = last_range(b" obj", pdf, filter.start)?.end;
        let dictionary_start = first_range(b"<<", pdf, object_start, Some(filter.start))?.start;
        let dictionary_end = matching_dictionary_end_bytes(pdf, dictionary_start)?;
        let dict = &pdf[dictionary_start..dictionary_end];
        if dict
            .windows(b"/Standard".len())
            .any(|window| window == b"/Standard")
        {
            return Some(dict.to_vec());
        }
    }
    None
}

fn empty_user_password_matches(params: &StandardEncryptionParameters) -> bool {
    match params.r {
        2 => {
            let key = encryption_key(params);
            rc4(&key, &PDF_PASSWORD_PADDING)
                .get(..params.u.len())
                .is_some_and(|candidate| candidate == params.u.as_slice())
        }
        3 | 4 => {
            let key = encryption_key(params);
            let mut digest = md5_bytes(
                [PDF_PASSWORD_PADDING.as_slice(), params.id0.as_slice()]
                    .concat()
                    .as_slice(),
            );
            digest = rc4(&key, &digest[..16]);
            for i in 1..20u8 {
                let round_key: Vec<u8> = key.iter().map(|byte| byte ^ i).collect();
                digest = rc4(&round_key, &digest);
            }
            params
                .u
                .get(..16)
                .is_some_and(|expected| expected == digest.as_slice())
        }
        _ => true,
    }
}

fn encryption_key(params: &StandardEncryptionParameters) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&PDF_PASSWORD_PADDING);
    input.extend_from_slice(&params.o);
    input.extend_from_slice(&params.p.to_le_bytes());
    input.extend_from_slice(&params.id0);
    if params.r >= 4 && !params.encrypt_metadata {
        input.extend_from_slice(&[0xff; 4]);
    }
    let mut digest = md5_bytes(&input);
    if params.r >= 3 {
        for _ in 0..50 {
            digest = md5_bytes(&digest[..params.key_len]);
        }
    }
    digest[..params.key_len].to_vec()
}

fn md5_bytes(input: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input);
    hasher.finalize().to_vec()
}

fn rc4(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256usize {
        j = (j + usize::from(s[i]) + usize::from(key[i % key.len()])) & 0xff;
        s.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    input
        .iter()
        .map(|byte| {
            i = (i + 1) & 0xff;
            j = (j + usize::from(s[i])) & 0xff;
            s.swap(i, j);
            byte ^ s[(usize::from(s[i]) + usize::from(s[j])) & 0xff]
        })
        .collect()
}

fn first_file_id(pdf: &[u8]) -> Option<Vec<u8>> {
    let id = first_range(b"/ID", pdf, 0, None)?;
    let mut i = id.end;
    while i < pdf.len() && is_whitespace(pdf[i]) {
        i += 1;
    }
    if pdf.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    while i < pdf.len() && is_whitespace(pdf[i]) {
        i += 1;
    }
    parse_hex_string(pdf, i).map(|(value, _)| value)
}

fn integer_after_name(bytes: &[u8], name: &[u8]) -> Option<i32> {
    let name_start = name_after(bytes, name)?;
    integer_at(bytes, name_start)
}

fn last_integer_after_name(bytes: &[u8], name: &[u8]) -> Option<i32> {
    let mut value = None;
    let mut search_from = 0usize;
    let mut needle = Vec::with_capacity(name.len() + 1);
    needle.push(b'/');
    needle.extend_from_slice(name);
    while let Some(range) = first_range(&needle, bytes, search_from, None) {
        search_from = range.end;
        let mut i = range.end;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        if let Some(parsed) = integer_at(bytes, i) {
            value = Some(parsed);
        }
    }
    value
}

fn integer_at(bytes: &[u8], start_at: usize) -> Option<i32> {
    let mut i = start_at;
    let sign = if bytes.get(i) == Some(&b'-') {
        i += 1;
        -1
    } else {
        1
    };
    let start = i;
    while i < bytes.len() && is_digit(bytes[i]) {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..i])
        .ok()?
        .parse::<i32>()
        .ok()
        .map(|value| sign * value)
}

fn bytes_after_name(bytes: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let value_start = name_after(bytes, name)?;
    match bytes.get(value_start) {
        Some(b'(') => parse_literal_string(bytes, value_start).map(|(value, _)| value),
        Some(b'<') if bytes.get(value_start + 1) != Some(&b'<') => {
            parse_hex_string(bytes, value_start).map(|(value, _)| value)
        }
        _ => None,
    }
}

fn name_after(bytes: &[u8], name: &[u8]) -> Option<usize> {
    let mut needle = Vec::with_capacity(name.len() + 1);
    needle.push(b'/');
    needle.extend_from_slice(name);
    let range = first_range(&needle, bytes, 0, None)?;
    let mut i = range.end;
    while i < bytes.len() && is_whitespace(bytes[i]) {
        i += 1;
    }
    Some(i)
}

fn name_followed_by_false(bytes: &[u8], name: &[u8]) -> bool {
    name_after(bytes, name).is_some_and(|start| bytes.get(start..start + 5) == Some(b"false"))
}

fn parse_literal_string(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    if bytes.get(start) != Some(&b'(') {
        return None;
    }
    let mut out = Vec::new();
    let mut depth = 1usize;
    let mut i = start + 1;
    while i < bytes.len() {
        let byte = bytes[i];
        i += 1;
        match byte {
            b'\\' => {
                let escaped = *bytes.get(i)?;
                i += 1;
                match escaped {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'\n' => {}
                    b'\r' => {
                        if bytes.get(i) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    b'0'..=b'7' => {
                        let mut value = escaped - b'0';
                        for _ in 0..2 {
                            if let Some(next @ b'0'..=b'7') = bytes.get(i).copied() {
                                value = value.saturating_mul(8).saturating_add(next - b'0');
                                i += 1;
                            } else {
                                break;
                            }
                        }
                        out.push(value);
                    }
                    other => out.push(other),
                }
            }
            b'(' => {
                depth += 1;
                out.push(byte);
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((out, i));
                }
                out.push(byte);
            }
            other => out.push(other),
        }
    }
    None
}

fn parse_hex_string(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    if bytes.get(start) != Some(&b'<') || bytes.get(start + 1) == Some(&b'<') {
        return None;
    }
    let mut hex = Vec::new();
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != b'>' {
        if !is_whitespace(bytes[i]) {
            hex.push(bytes[i]);
        }
        i += 1;
    }
    if bytes.get(i) != Some(&b'>') {
        return None;
    }
    if hex.len() % 2 == 1 {
        hex.push(b'0');
    }
    hex::decode(hex).ok().map(|value| (value, i + 1))
}

fn matching_dictionary_end_bytes(bytes: &[u8], dictionary_start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = dictionary_start;
    while i + 1 < bytes.len() {
        match (bytes[i], bytes[i + 1]) {
            (b'<', b'<') => {
                depth += 1;
                i += 2;
            }
            (b'>', b'>') => {
                depth = depth.checked_sub(1)?;
                i += 2;
                if depth == 0 {
                    return Some(i);
                }
            }
            (b'(', _) => {
                i = parse_literal_string(bytes, i)?.1;
            }
            _ => i += 1,
        }
    }
    None
}

fn signature_object_bounds(
    bytes: &[u8],
    br_range: Range<usize>,
) -> Option<(usize, usize, Option<PDFObjectId>)> {
    let obj_range = last_range(b" obj", bytes, br_range.start);
    let object_id = obj_range
        .as_ref()
        .and_then(|range| object_id_before_obj_keyword(range.start, bytes));
    let object_start = obj_range.map(|range| range.end).unwrap_or(br_range.start);
    let object_end = first_range(b"endobj", bytes, br_range.end, None)
        .map(|range| range.start)
        .unwrap_or(bytes.len());
    (object_start < object_end).then_some((object_start, object_end, object_id))
}

fn is_signature_dictionary_candidate(type_name: Option<&str>, sub_filter: Option<&str>) -> bool {
    matches!(type_name, Some("Sig" | "DocTimeStamp"))
        || matches!(
            sub_filter,
            Some(
                "adbe.pkcs7.detached" | "adbe.pkcs7.sha1" | "ETSI.CAdES.detached" | "ETSI.RFC3161"
            )
        )
}

fn is_usage_rights_signature_dictionary(
    bytes: &[u8],
    object_start: usize,
    object_end: usize,
) -> bool {
    let scan = String::from_utf8_lossy(&bytes[object_start..object_end]);
    contains_pdf_name_pair(&scan, "TransformMethod", "UR3")
        || (contains_pdf_name(&scan, "Perms") && contains_pdf_name(&scan, "UR3"))
}

fn parse_pdf_name_after(
    key: &str,
    bytes: &[u8],
    object_start: usize,
    object_end: usize,
) -> Option<String> {
    let range = first_range(key.as_bytes(), bytes, object_start, Some(object_end))?;
    let mut i = range.end;
    while i < object_end && is_whitespace(bytes[i]) {
        i += 1;
    }
    if i >= object_end || bytes[i] != b'/' {
        return None;
    }
    i += 1;
    let start = i;
    while i < object_end && is_pdf_name_byte(bytes[i]) {
        i += 1;
    }
    (i > start).then(|| String::from_utf8_lossy(&bytes[start..i]).to_string())
}

fn parse_modification_date(bytes: &[u8], object_start: usize, object_end: usize) -> Option<String> {
    let range = first_range(b"/M", bytes, object_start, Some(object_end))?;
    let mut i = range.end;
    while i < object_end && is_whitespace(bytes[i]) {
        i += 1;
    }
    if i >= object_end || bytes[i] != b'(' {
        return None;
    }
    let (literal, end) = parse_literal_string(bytes, i)?;
    if end > object_end {
        return None;
    }
    String::from_utf8(literal).ok()
}

fn incremental_objects(bytes: &[u8]) -> Vec<IncrementalObject> {
    let mut objects = Vec::new();
    let mut search_from = 0usize;
    while let Some(obj_range) = first_range(b" obj", bytes, search_from, None) {
        search_from = obj_range.end;
        let Some(id) = object_id_before_obj_keyword(obj_range.start, bytes) else {
            continue;
        };
        let Some(object_end) = first_range(b"endobj", bytes, obj_range.end, None) else {
            continue;
        };
        objects.push(IncrementalObject {
            id,
            start: obj_range.start,
            scan: ascii_outside_streams(&bytes[obj_range.end..object_end.start]),
        });
        search_from = object_end.end;
    }
    objects
}

fn latest_object_with_id(bytes: &[u8], id: PDFObjectId) -> Option<IncrementalObject> {
    incremental_objects(bytes)
        .into_iter()
        .rev()
        .find(|object| object.id == id)
}

fn latest_revision_objects(bytes: &[u8]) -> Vec<IncrementalObject> {
    let mut out = Vec::new();
    for object in incremental_objects(bytes).into_iter().rev() {
        if !out
            .iter()
            .any(|known: &IncrementalObject| known.id == object.id)
        {
            out.push(object);
        }
    }
    out.reverse();
    out
}

fn page_count(bytes: &[u8]) -> Option<usize> {
    let objects = incremental_objects_with_object_streams(bytes);
    let catalog = objects
        .iter()
        .rev()
        .find(|object| contains_pdf_name_pair(&object.scan, "Type", "Catalog"))?;
    let pages_id = reference_after_name(&catalog.scan, "Pages")?;
    let pages = objects.iter().rev().find(|object| object.id == pages_id)?;
    usize_after_name(&pages.scan, "Count")
}

fn incremental_objects_with_object_streams(bytes: &[u8]) -> Vec<IncrementalObject> {
    let mut objects = incremental_objects(bytes);
    objects.extend(object_stream_objects(bytes));
    objects.sort_by_key(|object| object.start);
    objects
}

fn object_stream_objects(bytes: &[u8]) -> Vec<IncrementalObject> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(obj_range) = first_range(b" obj", bytes, search_from, None) {
        search_from = obj_range.end;
        let Some(stream_range) = first_range(b"stream", bytes, obj_range.end, None) else {
            continue;
        };
        let Some(object_end) = first_range(b"endobj", bytes, obj_range.end, None) else {
            continue;
        };
        if stream_range.start > object_end.start {
            continue;
        }
        let header = &bytes[obj_range.end..stream_range.start];
        if !header
            .windows(b"/Type/ObjStm".len())
            .any(|window| window == b"/Type/ObjStm")
            && !header
                .windows(b"/Type /ObjStm".len())
                .any(|window| window == b"/Type /ObjStm")
        {
            continue;
        }
        let Some(first) = ascii_integer_after(header, b"First") else {
            continue;
        };
        let mut stream_start = stream_range.end;
        if bytes.get(stream_start) == Some(&b'\r') {
            stream_start += 1;
        }
        if bytes.get(stream_start) == Some(&b'\n') {
            stream_start += 1;
        }
        let Some(stream_end) =
            first_range(b"endstream", bytes, stream_start, Some(object_end.start))
                .map(|range| range.start)
        else {
            continue;
        };
        let mut decoder = ZlibDecoder::new(&bytes[stream_start..stream_end]);
        let mut decoded = Vec::new();
        if decoder.read_to_end(&mut decoded).is_err() || first > decoded.len() {
            continue;
        }
        let header_text = String::from_utf8_lossy(&decoded[..first]);
        let numbers: Vec<usize> = header_text
            .split_whitespace()
            .filter_map(|token| token.parse().ok())
            .collect();
        if numbers.len() < 2 {
            continue;
        }
        let body = &decoded[first..];
        for pair in numbers.chunks_exact(2).enumerate() {
            let (index, pair) = pair;
            let number = pair[0];
            let offset = pair[1];
            if offset >= body.len() {
                continue;
            }
            let next_offset = numbers
                .chunks_exact(2)
                .nth(index + 1)
                .map(|next| next[1])
                .unwrap_or(body.len())
                .min(body.len());
            if next_offset <= offset {
                continue;
            }
            out.push(IncrementalObject {
                id: PDFObjectId {
                    number,
                    generation: 0,
                },
                start: obj_range.start + offset,
                scan: ascii_outside_streams(&body[offset..next_offset]),
            });
        }
        search_from = object_end.end;
    }
    out
}

fn ascii_integer_after(bytes: &[u8], name: &[u8]) -> Option<usize> {
    integer_after_name(bytes, name).and_then(|value| usize::try_from(value).ok())
}

fn object_id_before_obj_keyword(index: usize, bytes: &[u8]) -> Option<PDFObjectId> {
    let mut i = index;
    while i > 0 && is_whitespace(bytes[i - 1]) {
        i -= 1;
    }
    let generation_end = i;
    while i > 0 && is_digit(bytes[i - 1]) {
        i -= 1;
    }
    let generation = std::str::from_utf8(&bytes[i..generation_end])
        .ok()?
        .parse()
        .ok()?;
    while i > 0 && is_whitespace(bytes[i - 1]) {
        i -= 1;
    }
    let number_end = i;
    while i > 0 && is_digit(bytes[i - 1]) {
        i -= 1;
    }
    let number = std::str::from_utf8(&bytes[i..number_end])
        .ok()?
        .parse()
        .ok()?;
    Some(PDFObjectId { number, generation })
}

fn catalog_update_only_adds_dss(
    object: &IncrementalObject,
    prior_objects: &[IncrementalObject],
) -> bool {
    contains_pdf_name_pair(&object.scan, "Type", "Catalog")
        && contains_pdf_name(&object.scan, "DSS")
        && prior_objects
            .iter()
            .rev()
            .find(|prior| prior.id == object.id)
            .map(|prior| {
                normalized_pdf_object_text_removing_dss(&prior.scan)
                    == normalized_pdf_object_text_removing_dss(&object.scan)
            })
            .unwrap_or(false)
}

fn catalog_update_only_adds_validation_material(
    object: &IncrementalObject,
    prior_objects: &[IncrementalObject],
    tail_objects: &[IncrementalObject],
) -> bool {
    if !contains_pdf_name_pair(&object.scan, "Type", "Catalog")
        || !contains_pdf_name(&object.scan, "DSS")
    {
        return false;
    }
    let Some(prior) = prior_objects
        .iter()
        .rev()
        .find(|prior| prior.id == object.id)
    else {
        return false;
    };
    let prior_fields = array_references_after_name(&prior.scan, "Fields");
    let current_fields = array_references_after_name(&object.scan, "Fields");
    let added_fields: Vec<_> = current_fields
        .into_iter()
        .filter(|field| !prior_fields.contains(field))
        .collect();
    if added_fields.is_empty()
        || !added_fields
            .iter()
            .all(|field| is_document_timestamp_field(*field, tail_objects))
    {
        return false;
    }

    let current_without_dss = normalized_pdf_object_text_removing_dss(&object.scan);
    let current_without_allowed_refs =
        pdf_object_text_removing_references(&current_without_dss, &added_fields);
    normalized_pdf_object_syntax_text(&normalized_pdf_object_text_removing_dss(&prior.scan))
        == normalized_pdf_object_syntax_text(&current_without_allowed_refs)
}

fn object_changed_from_prior_revision(
    object: &IncrementalObject,
    prior_objects: &[IncrementalObject],
) -> bool {
    prior_objects
        .iter()
        .rev()
        .find(|prior| prior.id == object.id)
        .map(|prior| {
            normalized_pdf_object_text(&prior.scan) != normalized_pdf_object_text(&object.scan)
        })
        .unwrap_or(false)
}

fn usize_after_name(text: &str, name: &str) -> Option<usize> {
    let needle = format!("/{name}");
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(relative_start) = text[search_from..].find(&needle) {
        let name_start = search_from + relative_start;
        let name_end = name_start + needle.len();
        if bytes
            .get(name_end)
            .map(|byte| is_pdf_name_byte(*byte))
            .unwrap_or(false)
        {
            search_from = name_end;
            continue;
        }
        let mut i = name_end;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        let number_start = i;
        while i < bytes.len() && is_digit(bytes[i]) {
            i += 1;
        }
        if number_start == i {
            search_from = name_end;
            continue;
        }
        return text[number_start..i].parse().ok();
    }
    None
}

fn validation_data_object_update(
    object: &IncrementalObject,
    prior_objects: &[IncrementalObject],
) -> bool {
    prior_objects
        .iter()
        .rev()
        .find(|prior| prior.id == object.id)
        .map(|prior| {
            object_looks_like_dss_dictionary(&prior.scan)
                && object_looks_like_dss_dictionary(&object.scan)
        })
        .unwrap_or(false)
}

fn array_references_after_name(text: &str, name: &str) -> Vec<PDFObjectId> {
    let needle = format!("/{name}");
    let Some(name_start) = text.find(&needle) else {
        return Vec::new();
    };
    let Some(array_start) = text[name_start..].find('[').map(|index| name_start + index) else {
        return Vec::new();
    };
    let Some(array_end) = text[array_start..]
        .find(']')
        .map(|index| array_start + index)
    else {
        return Vec::new();
    };
    object_references(&text[array_start..=array_end])
}

fn array_references_in_dictionary_after_name(
    text: &str,
    dictionary_name: &str,
    array_name: &str,
) -> Option<Vec<PDFObjectId>> {
    let needle = format!("/{dictionary_name}");
    let dictionary_name_start = text.find(&needle)?;
    let dictionary_start = text[dictionary_name_start..]
        .find("<<")
        .map(|index| dictionary_name_start + index)?;
    let dictionary_end = matching_dictionary_end(text, dictionary_start)?;
    let references =
        array_references_after_name(&text[dictionary_start..dictionary_end], array_name);
    (!references.is_empty()).then_some(references)
}

fn matching_dictionary_end(text: &str, dictionary_start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = dictionary_start;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'>' && bytes[i + 1] == b'>' {
            depth = depth.checked_sub(1)?;
            i += 2;
            if depth == 0 {
                return Some(i);
            }
            continue;
        }
        i += 1;
    }
    None
}

fn is_document_timestamp_field(id: PDFObjectId, tail_objects: &[IncrementalObject]) -> bool {
    let Some(field) = tail_objects.iter().rev().find(|object| object.id == id) else {
        return false;
    };
    if object_is_document_timestamp_signature(&field.scan) {
        return true;
    }
    object_references(&field.scan).iter().any(|reference| {
        tail_objects
            .iter()
            .rev()
            .find(|object| object.id == *reference)
            .map(|object| object_is_document_timestamp_signature(&object.scan))
            .unwrap_or(false)
    })
}

fn object_is_document_timestamp_signature(text: &str) -> bool {
    contains_pdf_name_pair(text, "Type", "DocTimeStamp")
        || contains_pdf_name_pair(text, "SubFilter", "ETSI.RFC3161")
}

fn signature_field_ids_referencing_signature(
    revision: &[u8],
    signature_id: PDFObjectId,
) -> Vec<PDFObjectId> {
    acroform_signature_fields(revision)
        .into_iter()
        .filter(|field| field.value == Some(signature_id))
        .map(|field| field.id)
        .collect()
}

#[derive(Clone, Copy)]
struct SignatureFieldRef {
    id: PDFObjectId,
    value: Option<PDFObjectId>,
}

fn acroform_signature_fields(revision: &[u8]) -> Vec<SignatureFieldRef> {
    let objects = latest_revision_objects(revision);
    let Some(catalog) = objects
        .iter()
        .rev()
        .find(|object| contains_pdf_name_pair(&object.scan, "Type", "Catalog"))
    else {
        return Vec::new();
    };
    let fields = acroform_field_references(catalog, &objects);
    let mut out = Vec::new();
    let mut visited = Vec::new();
    for field in fields {
        collect_signature_fields(field, None, &objects, &mut visited, &mut out);
    }
    out
}

fn acroform_field_references(
    catalog: &IncrementalObject,
    objects: &[IncrementalObject],
) -> Vec<PDFObjectId> {
    if let Some(acroform_id) = reference_after_name(&catalog.scan, "AcroForm") {
        if let Some(acroform) = objects.iter().find(|object| object.id == acroform_id) {
            return array_references_after_name(&acroform.scan, "Fields");
        }
    }
    array_references_in_dictionary_after_name(&catalog.scan, "AcroForm", "Fields")
        .or_else(|| {
            let fields = array_references_after_name(&catalog.scan, "Fields");
            (!fields.is_empty()).then_some(fields)
        })
        .unwrap_or_default()
}

fn collect_signature_fields(
    id: PDFObjectId,
    inherited_ft_sig: Option<bool>,
    objects: &[IncrementalObject],
    visited: &mut Vec<PDFObjectId>,
    out: &mut Vec<SignatureFieldRef>,
) {
    if visited.contains(&id) {
        return;
    }
    visited.push(id);
    let Some(object) = objects.iter().find(|object| object.id == id) else {
        return;
    };
    let field_type_sig =
        contains_pdf_name_pair(&object.scan, "FT", "Sig") || inherited_ft_sig.unwrap_or(false);
    let value = field_value_reference(&object.scan);
    if field_type_sig && value.is_some() {
        out.push(SignatureFieldRef { id, value });
    }
    for kid in array_references_after_name(&object.scan, "Kids") {
        collect_signature_fields(kid, Some(field_type_sig), objects, visited, out);
    }
}

fn object_looks_like_dss_dictionary(text: &str) -> bool {
    contains_pdf_name_pair(text, "Type", "DSS")
        || ["VRI", "Certs", "OCSPs", "CRLs", "OCSP", "CRL"]
            .iter()
            .any(|name| contains_pdf_name(text, name))
}

fn object_looks_like_document_metadata(text: &str) -> bool {
    !has_disallowed_validation_tail_marker(text)
        && (contains_pdf_name_pair(text, "Type", "Metadata")
            || [
                "Author",
                "CreationDate",
                "Creator",
                "Keywords",
                "ModDate",
                "Producer",
                "Subject",
                "Title",
            ]
            .iter()
            .any(|name| contains_pdf_name(text, name)))
}

fn has_disallowed_validation_tail_marker(text: &str) -> bool {
    [
        "/Type /Page",
        "/Type /Pages",
        "/Type /ObjStm",
        "/Subtype /Widget",
        "/Annots",
        "/Contents",
        "/AcroForm",
        "/OpenAction",
        "/AA",
        "/Names",
        "/JavaScript",
        "/JS",
        "/Launch",
        "/EmbeddedFiles",
        "/RichMedia",
        "/GoTo",
        "/GoToE",
        "/GoToR",
        "/SubmitForm",
        "/ImportData",
        "/URI",
        "/AF",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn normalized_pdf_object_text_removing_dss(text: &str) -> String {
    normalized_pdf_catalog_text(&pdf_object_text_removing_catalog_validation_additions(text))
}

fn normalized_pdf_catalog_text(text: &str) -> String {
    let mut spaced = String::with_capacity(text.len() * 2);
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '<' if chars.peek() == Some(&'<') => {
                let _ = chars.next();
                spaced.push_str(" << ");
            }
            '>' if chars.peek() == Some(&'>') => {
                let _ = chars.next();
                spaced.push_str(" >> ");
            }
            '[' | ']' => {
                spaced.push(' ');
                spaced.push(ch);
                spaced.push(' ');
            }
            '(' => {
                spaced.push(' ');
                spaced.push(ch);
            }
            ')' => {
                spaced.push(ch);
                spaced.push(' ');
            }
            '/' => {
                spaced.push(' ');
                spaced.push(ch);
            }
            _ => spaced.push(ch),
        }
    }
    normalized_pdf_object_text(&spaced)
}

fn pdf_object_text_removing_catalog_validation_additions(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if starts_pdf_name(bytes, i, b"DSS") {
            if let Some(end) = pdf_name_value_end(bytes, i + 4) {
                i = end;
                continue;
            }
        }
        if starts_pdf_name(bytes, i, b"Extensions") {
            if let Some(end) = pdf_name_value_end(bytes, i + 11) {
                let value = String::from_utf8_lossy(&bytes[i..end]);
                if contains_pdf_name(&value, "ADBE") || contains_pdf_name(&value, "ESIC") {
                    i = end;
                    continue;
                }
            }
        }
        if starts_pdf_name(bytes, i, b"Version") {
            if let Some(end) = pdf_name_value_end(bytes, i + 8) {
                let value = String::from_utf8_lossy(&bytes[i..end]);
                if contains_pdf_name(&value, "1.7") {
                    i = end;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn starts_pdf_name(bytes: &[u8], offset: usize, name: &[u8]) -> bool {
    bytes.get(offset) == Some(&b'/')
        && bytes
            .get(offset + 1..offset + 1 + name.len())
            .is_some_and(|candidate| candidate == name)
        && bytes
            .get(offset + 1 + name.len())
            .map(|byte| !is_pdf_name_byte(*byte))
            .unwrap_or(true)
}

fn pdf_name_value_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    while i < bytes.len() && is_whitespace(bytes[i]) {
        i += 1;
    }
    if i + 1 < bytes.len() && bytes[i] == b'<' && bytes[i + 1] == b'<' {
        return matching_dictionary_end_bytes(bytes, i);
    }
    if bytes.get(i) == Some(&b'/') {
        i += 1;
        while i < bytes.len() && is_pdf_name_byte(bytes[i]) {
            i += 1;
        }
        return Some(i);
    }
    let number_start = i;
    while i < bytes.len() && is_digit(bytes[i]) {
        i += 1;
    }
    if i == number_start {
        return None;
    }
    while i < bytes.len() && is_whitespace(bytes[i]) {
        i += 1;
    }
    let generation_start = i;
    while i < bytes.len() && is_digit(bytes[i]) {
        i += 1;
    }
    if i == generation_start {
        return None;
    }
    while i < bytes.len() && is_whitespace(bytes[i]) {
        i += 1;
    }
    (bytes.get(i) == Some(&b'R')).then_some(i + 1)
}

fn normalized_pdf_object_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalized_pdf_object_syntax_text(text: &str) -> String {
    let mut spaced = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '[' | ']') {
            spaced.push(' ');
            spaced.push(ch);
            spaced.push(' ');
        } else {
            spaced.push(ch);
        }
    }
    normalized_pdf_object_text(&spaced)
}

fn pdf_object_text_removing_references(text: &str, references: &[PDFObjectId]) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if is_digit(bytes[i]) {
            let number_start = i;
            while i < bytes.len() && is_digit(bytes[i]) {
                i += 1;
            }
            let number_end = i;
            let mut j = i;
            while j < bytes.len() && is_whitespace(bytes[j]) {
                j += 1;
            }
            let generation_start = j;
            while j < bytes.len() && is_digit(bytes[j]) {
                j += 1;
            }
            let generation_end = j;
            let mut k = j;
            while k < bytes.len() && is_whitespace(bytes[k]) {
                k += 1;
            }
            if bytes.get(k) == Some(&b'R') {
                let number = text[number_start..number_end].parse::<usize>().ok();
                let generation = text[generation_start..generation_end].parse::<usize>().ok();
                if let (Some(number), Some(generation)) = (number, generation) {
                    if references.contains(&PDFObjectId { number, generation }) {
                        i = k + 1;
                        continue;
                    }
                }
            }
            out.extend_from_slice(&bytes[number_start..i]);
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn object_references(text: &str) -> Vec<PDFObjectId> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && !is_digit(bytes[i]) {
            i += 1;
        }
        let number_start = i;
        while i < bytes.len() && is_digit(bytes[i]) {
            i += 1;
        }
        if number_start == i {
            break;
        }
        let Ok(number) = text[number_start..i].parse::<usize>() else {
            continue;
        };
        let mut j = i;
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        let generation_start = j;
        while j < bytes.len() && is_digit(bytes[j]) {
            j += 1;
        }
        if generation_start == j {
            i = j;
            continue;
        }
        let Ok(generation) = text[generation_start..j].parse::<usize>() else {
            i = j;
            continue;
        };
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        if bytes.get(j) == Some(&b'R') {
            let after = j + 1;
            if after == bytes.len() || !is_pdf_name_byte(bytes[after]) {
                push_unique(&mut out, PDFObjectId { number, generation });
            }
        }
        i = j.saturating_add(1);
    }
    out
}

fn field_value_reference(text: &str) -> Option<PDFObjectId> {
    reference_after_name(text, "V")
}

fn reference_after_name(text: &str, name: &str) -> Option<PDFObjectId> {
    let needle = format!("/{name}");
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(relative_start) = text[search_from..].find(&needle) {
        let name_start = search_from + relative_start;
        let name_end = name_start + needle.len();
        if bytes
            .get(name_end)
            .map(|byte| is_pdf_name_byte(*byte))
            .unwrap_or(false)
        {
            search_from = name_end;
            continue;
        }
        let mut i = name_end;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        let number_start = i;
        while i < bytes.len() && is_digit(bytes[i]) {
            i += 1;
        }
        if number_start == i {
            search_from = name_end;
            continue;
        }
        let number = text[number_start..i].parse::<usize>().ok()?;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        let generation_start = i;
        while i < bytes.len() && is_digit(bytes[i]) {
            i += 1;
        }
        if generation_start == i {
            search_from = name_end;
            continue;
        }
        let generation = text[generation_start..i].parse::<usize>().ok()?;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        if bytes.get(i) == Some(&b'R') {
            return Some(PDFObjectId { number, generation });
        }
        search_from = name_end;
    }
    None
}

fn contains_pdf_name(text: &str, name: &str) -> bool {
    let needle = format!("/{name}");
    let bytes = text.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > bytes.len() {
        return false;
    }
    for i in 0..=bytes.len() - needle.len() {
        if &bytes[i..i + needle.len()] == needle {
            let end = i + needle.len();
            if end == bytes.len() || !is_pdf_name_byte(bytes[end]) {
                return true;
            }
        }
    }
    false
}

fn contains_pdf_name_pair(text: &str, key: &str, value: &str) -> bool {
    let key_needle = format!("/{key}");
    let value_needle = format!("/{value}");
    let bytes = text.as_bytes();
    let mut search_from = 0usize;
    while let Some(relative_start) = text[search_from..].find(&key_needle) {
        let key_start = search_from + relative_start;
        let key_end = key_start + key_needle.len();
        if bytes
            .get(key_end)
            .map(|byte| is_pdf_name_byte(*byte))
            .unwrap_or(false)
        {
            search_from = key_end;
            continue;
        }
        let mut i = key_end;
        while i < bytes.len() && is_whitespace(bytes[i]) {
            i += 1;
        }
        if text[i..].starts_with(&value_needle)
            && bytes
                .get(i + value_needle.len())
                .map(|byte| !is_pdf_name_byte(*byte))
                .unwrap_or(true)
        {
            return true;
        }
        search_from = key_end;
    }
    false
}

fn ascii_outside_streams(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if data[i..].starts_with(b"stream") {
            i += b"stream".len();
            while i < data.len() && (data[i] == b'\r' || data[i] == b'\n') {
                i += 1;
            }
            while i < data.len() && !data[i..].starts_with(b"endstream") {
                i += 1;
            }
            if i < data.len() {
                i += b"endstream".len();
            }
            out.push(b' ');
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn first_range(
    needle: &[u8],
    haystack: &[u8],
    from: usize,
    until: Option<usize>,
) -> Option<Range<usize>> {
    let limit = until.unwrap_or(haystack.len()).min(haystack.len());
    if needle.is_empty() || from + needle.len() > limit {
        return None;
    }
    for i in from..=limit - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i..i + needle.len());
        }
    }
    None
}

fn last_range(needle: &[u8], haystack: &[u8], before: usize) -> Option<Range<usize>> {
    let limit = before.min(haystack.len());
    if needle.is_empty() || needle.len() > limit {
        return None;
    }
    let mut i = limit - needle.len();
    loop {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i..i + needle.len());
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

fn final_eof_end(bytes: &[u8]) -> Option<usize> {
    last_range(b"%%EOF", bytes, bytes.len()).map(|range| range.end)
}

fn push_unique<T: Eq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

fn is_pdf_name_byte(b: u8) -> bool {
    b > 0x20
        && b < 0x7f
        && !matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acroform_traversal_finds_nested_duplicate_signature_fields() {
        let pdf = br#"
1 0 obj
<< /Type /Catalog /AcroForm 2 0 R >>
endobj
2 0 obj
<< /Fields [3 0 R] >>
endobj
3 0 obj
<< /FT /Sig /Kids [4 0 R 5 0 R] >>
endobj
4 0 obj
<< /Subtype /Widget /V 8 0 R >>
endobj
5 0 obj
<< /Subtype /Widget /V 8 0 R >>
endobj
8 0 obj
<< /Type /Sig >>
endobj
"#;
        let sig = test_sig_dict(8, pdf.len());

        assert!(signature_has_duplicate_field_references_in_signed_revision(
            pdf, &sig
        ));
    }

    #[test]
    fn acroform_traversal_uses_latest_field_revision() {
        let pdf = br#"
1 0 obj
<< /Type /Catalog /AcroForm << /Fields [3 0 R] >> >>
endobj
3 0 obj
<< /FT /Sig /V 8 0 R >>
endobj
3 0 obj
<< /FT /Sig /V 9 0 R >>
endobj
8 0 obj
<< /Type /Sig >>
endobj
"#;
        let sig = test_sig_dict(8, pdf.len());

        assert!(!signature_has_duplicate_field_references_in_signed_revision(pdf, &sig));
        assert!(signature_field_ids_referencing_signature(
            pdf,
            PDFObjectId {
                number: 8,
                generation: 0
            }
        )
        .is_empty());
    }

    #[test]
    fn oversized_byte_range_integer_is_rejected_without_overflow() {
        let pdf = br#"%PDF-1.7
1 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached
   /ByteRange [0 999999999999999999999999999999999999999 0 0]
   /Contents <3000> >>
endobj
%%EOF"#;

        assert!(SigDict::parse_all(pdf).is_empty());
    }

    #[test]
    fn modification_date_decodes_pdf_literal_string_escapes() {
        let pdf = br#"<< /Type /Sig /M (D\07220260603115804Z) >>"#;

        assert_eq!(
            parse_modification_date(pdf, 0, pdf.len()),
            Some("D:20260603115804Z".to_owned())
        );
    }

    fn test_sig_dict(object_number: usize, signed_revision_size: usize) -> SigDict {
        SigDict {
            object_number: Some(object_number),
            object_generation: Some(0),
            object_start: 0,
            byte_range: vec![0, 0, signed_revision_size, 0],
            cms_bytes: Vec::new(),
            cms_hex_length: 0,
            contents_placeholder_range: 0..0,
            modification_date: None,
            type_name: Some("Sig".to_owned()),
            sub_filter: None,
            usage_rights: false,
        }
    }
}
