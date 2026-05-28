#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv {
    pub tag: u8,
    pub content: Vec<u8>,
    pub full_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    idx: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.idx).copied()
    }

    pub fn skip_one_tlv(&mut self) -> bool {
        self.read_tlv().is_some()
    }

    pub fn read_tlv(&mut self) -> Option<Tlv> {
        if self.idx >= self.buf.len() {
            return None;
        }
        let start = self.idx;
        let tag = *self.buf.get(self.idx)?;
        self.idx += 1;
        let first = usize::from(*self.buf.get(self.idx)?);
        self.idx += 1;
        let length = if first < 0x80 {
            first
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 || self.idx + n > self.buf.len() {
                return None;
            }
            let mut v = 0usize;
            for _ in 0..n {
                v = (v << 8) | usize::from(self.buf[self.idx]);
                self.idx += 1;
            }
            v
        };
        if self.idx + length > self.buf.len() {
            return None;
        }
        let content = self.buf[self.idx..self.idx + length].to_vec();
        let full_bytes = self.buf[start..self.idx + length].to_vec();
        self.idx += length;
        Some(Tlv {
            tag,
            content,
            full_bytes,
        })
    }
}

pub fn int_value(content: &[u8]) -> usize {
    content
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
}

pub fn oid_string(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let first = usize::from(content[0]);
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut v = 0usize;
    for b in &content[1..] {
        v = (v << 7) | usize::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(v.to_string());
            v = 0;
        }
    }
    parts.join(".")
}

pub fn first_octet_string(data: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(data);
    while let Some(tlv) = reader.read_tlv() {
        if tlv.tag == 0x04 {
            return Some(tlv.content);
        }
    }
    None
}

pub fn first_time_string(data: &[u8]) -> Option<String> {
    let mut reader = Reader::new(data);
    while let Some(tlv) = reader.read_tlv() {
        if (tlv.tag == 0x17 || tlv.tag == 0x18) && !tlv.content.is_empty() {
            return String::from_utf8(tlv.content).ok();
        }
    }
    None
}

pub fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut value = length;
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.insert(0, (value & 0xff) as u8);
        value >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

pub fn normalized_asn1_first_object(data: &[u8]) -> Option<Vec<u8>> {
    let mut index = 0usize;
    normalized_asn1_element(data, &mut index)
}

fn normalized_asn1_element(bytes: &[u8], index: &mut usize) -> Option<Vec<u8>> {
    if *index + 2 > bytes.len() || (bytes[*index] == 0 && bytes[*index + 1] == 0) {
        return None;
    }
    let first_tag = bytes[*index];
    let constructed = (first_tag & 0x20) != 0;
    let mut tag_bytes = vec![first_tag];
    *index += 1;
    if first_tag & 0x1f == 0x1f {
        loop {
            let b = *bytes.get(*index)?;
            tag_bytes.push(b);
            *index += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let first = usize::from(*bytes.get(*index)?);
    *index += 1;
    if first == 0x80 {
        if !constructed {
            return None;
        }
        let mut content = Vec::new();
        loop {
            if *index + 2 > bytes.len() {
                return None;
            }
            if bytes[*index] == 0 && bytes[*index + 1] == 0 {
                *index += 2;
                break;
            }
            content.extend(normalized_asn1_element(bytes, index)?);
        }
        let mut out = tag_bytes;
        out.extend(der_length(content.len()));
        out.extend(content);
        return Some(out);
    }
    let length = if first < 0x80 {
        first
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 || *index + n > bytes.len() {
            return None;
        }
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 8) | usize::from(bytes[*index]);
            *index += 1;
        }
        v
    };
    if *index + length > bytes.len() {
        return None;
    }
    let mut content = bytes[*index..*index + length].to_vec();
    *index += length;
    if constructed {
        let mut child_index = 0usize;
        let mut normalized = Vec::new();
        while child_index < content.len() {
            normalized.extend(normalized_asn1_element(&content, &mut child_index)?);
        }
        content = normalized;
    }
    let mut out = tag_bytes;
    out.extend(der_length(content.len()));
    out.extend(content);
    Some(out)
}
