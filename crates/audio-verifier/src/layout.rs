//! The channel layout: one speaker position per channel, in channel order, as the codes of the
//! Move `audio_channel_layout::ChannelLayout`. The codes are the bit positions of the WAVE
//! channel mask (RFC 9639, section 8.6.2), 0 (front left) to 17 (top rear right), and
//! [`UNASSIGNED`] for a channel with no speaker position.

use crate::Error;

/// The code of a channel that is not assigned to a speaker position.
pub const UNASSIGNED: u8 = 255;

/// The highest speaker position RFC 9639 defines, top rear right.
pub const MAX_SPEAKER: u8 = 17;

/// The Vorbis comment field that overrides the default layout. Its name and value are compared
/// without regard to ASCII case.
pub const CHANNEL_MASK_FIELD: &str = "WAVEFORMATEXTENSIBLE_CHANNEL_MASK";

const FL: u8 = 0;
const FR: u8 = 1;
const FC: u8 = 2;
const LFE: u8 = 3;
const BL: u8 = 4;
const BR: u8 = 5;
const BC: u8 = 8;
const SL: u8 = 9;
const SR: u8 = 10;

/// The default layout of `channels` channels, FLAC's channel assignment (RFC 9639, section
/// 9.1.3) in the speaker positions libFLAC's reference decoder gives it when it writes WAVE
/// (`src/flac/decode.c`, masks 0x4, 0x3, 0x7, 0x33, 0x607, 0x60f, 0x70f and 0x63f): mono is
/// front center, and the "back/surround" pair of five and six channels is side left and right.
pub fn default_layout(channels: u8) -> Vec<u8> {
    let speakers: &[u8] = match channels {
        1 => &[FC],
        2 => &[FL, FR],
        3 => &[FL, FR, FC],
        4 => &[FL, FR, BL, BR],
        5 => &[FL, FR, FC, SL, SR],
        6 => &[FL, FR, FC, LFE, SL, SR],
        7 => &[FL, FR, FC, LFE, BC, SL, SR],
        8 => &[FL, FR, FC, LFE, BL, BR, SL, SR],
        _ => unreachable!("FLAC has 1 to 8 channels"),
    };
    speakers.to_vec()
}

/// The layout of `channels` channels under a channel mask: each set bit, lowest first, is the
/// position of the next channel, and channels past the mask's bits are [`UNASSIGNED`]
/// (RFC 9639: a mask "MAY code for fewer channels than are present", and 0 assigns none).
/// A mask with more bits than channels, or with bits above [`MAX_SPEAKER`], is refused.
pub fn masked_layout(channels: u8, mask: u32) -> Result<Vec<u8>, Error> {
    if mask >> (MAX_SPEAKER + 1) != 0 {
        return Err(Error::ChannelMaskBits(mask));
    }
    let speakers: Vec<u8> = (0..=MAX_SPEAKER)
        .filter(|bit| mask & (1 << bit) != 0)
        .collect();
    if speakers.len() > usize::from(channels) {
        return Err(Error::ChannelMaskChannels { mask, channels });
    }
    let mut layout = speakers;
    layout.resize(usize::from(channels), UNASSIGNED);
    Ok(layout)
}

/// The layout of `channels` channels: the default, or the one `mask` sets.
pub fn channel_layout(channels: u8, mask: Option<u32>) -> Result<Vec<u8>, Error> {
    match mask {
        None => Ok(default_layout(channels)),
        Some(mask) => masked_layout(channels, mask),
    }
}

/// Reads a little-endian `u32` length at `*at` and the bytes it counts.
fn counted<'a>(body: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let length = body.get(*at..*at + 4)?;
    let length = u32::from_le_bytes(length.try_into().ok()?) as usize;
    let start = *at + 4;
    let bytes = body.get(start..start.checked_add(length)?)?;
    *at = start + length;
    Some(bytes)
}

/// Parses `0x` and hexadecimal digits, either case, leading zeros allowed.
fn parse_mask(value: &[u8]) -> Option<u32> {
    let digits = value
        .strip_prefix(b"0x")
        .or_else(|| value.strip_prefix(b"0X"))?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let significant = &digits[digits.iter().take_while(|&&digit| digit == b'0').count()..];
    if significant.len() > 8 {
        return None;
    }
    let text = std::str::from_utf8(significant).ok()?;
    if text.is_empty() {
        return Some(0);
    }
    u32::from_str_radix(text, 16).ok()
}

/// Finds the channel mask in a VORBIS_COMMENT block's body, refusing a body whose lengths do
/// not add up to it exactly, or a mask that is not `0x` and hexadecimal digits.
pub(crate) fn find_channel_mask(body: &[u8]) -> Result<Option<u32>, Error> {
    let mut at = 0;
    counted(body, &mut at).ok_or(Error::VorbisComment)?;
    let count = body.get(at..at + 4).ok_or(Error::VorbisComment)?;
    let count = u32::from_le_bytes(count.try_into().expect("4 bytes"));
    at += 4;
    let mut mask = None;
    for _ in 0..count {
        let comment = counted(body, &mut at).ok_or(Error::VorbisComment)?;
        let Some(equals) = comment.iter().position(|&byte| byte == b'=') else {
            continue;
        };
        let (name, value) = (&comment[..equals], &comment[equals + 1..]);
        if !name.eq_ignore_ascii_case(CHANNEL_MASK_FIELD.as_bytes()) {
            continue;
        }
        if mask.is_some() {
            return Err(Error::ChannelMaskRepeated);
        }
        let parsed = parse_mask(value).ok_or_else(|| {
            Error::ChannelMaskValue(String::from_utf8_lossy(value).chars().take(64).collect())
        })?;
        mask = Some(parsed);
    }
    if at != body.len() {
        return Err(Error::VorbisComment);
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(comments: &[&str]) -> Vec<u8> {
        let vendor = b"reference libFLAC 1.5.0 20250211";
        let mut out = (vendor.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(vendor);
        out.extend_from_slice(&(comments.len() as u32).to_le_bytes());
        for comment in comments {
            out.extend_from_slice(&(comment.len() as u32).to_le_bytes());
            out.extend_from_slice(comment.as_bytes());
        }
        out
    }

    #[test]
    fn defaults_follow_the_flac_channel_assignment() {
        assert_eq!(default_layout(1), [2]);
        assert_eq!(default_layout(2), [0, 1]);
        assert_eq!(default_layout(3), [0, 1, 2]);
        assert_eq!(default_layout(4), [0, 1, 4, 5]);
        assert_eq!(default_layout(5), [0, 1, 2, 9, 10]);
        assert_eq!(default_layout(6), [0, 1, 2, 3, 9, 10]);
        assert_eq!(default_layout(7), [0, 1, 2, 3, 8, 9, 10]);
        assert_eq!(default_layout(8), [0, 1, 2, 3, 4, 5, 9, 10]);
    }

    #[test]
    fn defaults_are_the_reference_decoders_masks() {
        let masks = [0x4, 0x3, 0x7, 0x33, 0x607, 0x60f, 0x70f, 0x63f];
        for (channels, mask) in (1..=8).zip(masks) {
            assert_eq!(masked_layout(channels, mask), Ok(default_layout(channels)));
        }
    }

    #[test]
    fn masks_assign_channels_in_bit_order() {
        // RFC 9639's examples: one LFE channel; front left and right, top front left and right;
        // front center, back center, top front center and top rear center.
        assert_eq!(masked_layout(1, 0x8), Ok(vec![3]));
        assert_eq!(masked_layout(4, 0x5003), Ok(vec![0, 1, 12, 14]));
        assert_eq!(masked_layout(4, 0x12104), Ok(vec![2, 8, 13, 16]));
        // Ambisonics UHJ: two front channels, two unassigned.
        assert_eq!(masked_layout(4, 0x3), Ok(vec![0, 1, 255, 255]));
        assert_eq!(masked_layout(2, 0), Ok(vec![255, 255]));
        assert_eq!(masked_layout(1, 1 << 17), Ok(vec![17]));
    }

    #[test]
    fn masks_beyond_the_channels_or_the_table_are_refused() {
        assert_eq!(
            masked_layout(2, 0x7),
            Err(Error::ChannelMaskChannels {
                mask: 0x7,
                channels: 2
            })
        );
        assert_eq!(
            masked_layout(8, 1 << 18),
            Err(Error::ChannelMaskBits(1 << 18))
        );
        assert_eq!(
            masked_layout(8, 0x8000_0000),
            Err(Error::ChannelMaskBits(0x8000_0000))
        );
    }

    #[test]
    fn the_mask_field_is_found_without_regard_to_case() {
        assert_eq!(find_channel_mask(&body(&[])), Ok(None));
        assert_eq!(
            find_channel_mask(&body(&["TITLE=x", "ARTIST=y=z", "novalue"])),
            Ok(None)
        );
        for comment in [
            "WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x3",
            "waveformatextensible_channel_mask=0X0003",
            "WaveFormatExtensible_Channel_Mask=0x00000000003",
        ] {
            assert_eq!(
                find_channel_mask(&body(&["TITLE=x", comment])),
                Ok(Some(3)),
                "{comment}"
            );
        }
        assert_eq!(
            find_channel_mask(&body(&["WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x3fFfF"])),
            Ok(Some(0x3ffff))
        );
        assert_eq!(
            find_channel_mask(&body(&["WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x0"])),
            Ok(Some(0))
        );
    }

    #[test]
    fn malformed_masks_and_comments_are_refused() {
        for value in [
            "3",
            "0x",
            "0x-1",
            "0x1g",
            " 0x3",
            "0x3 ",
            "0x123456789",
            "+0x3",
        ] {
            let comment = format!("WAVEFORMATEXTENSIBLE_CHANNEL_MASK={value}");
            assert_eq!(
                find_channel_mask(&body(&[&comment])),
                Err(Error::ChannelMaskValue(value.into())),
                "{value}"
            );
        }
        let twice = [
            "WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x3",
            "WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x3",
        ];
        assert_eq!(
            find_channel_mask(&body(&twice)),
            Err(Error::ChannelMaskRepeated)
        );
        let whole = body(&["TITLE=x"]);
        assert_eq!(
            find_channel_mask(&whole[..whole.len() - 1]),
            Err(Error::VorbisComment)
        );
        assert_eq!(
            find_channel_mask(&[&whole[..], &[0]].concat()),
            Err(Error::VorbisComment)
        );
        let mut overcounted = whole.clone();
        overcounted[36] = 2;
        assert_eq!(find_channel_mask(&overcounted), Err(Error::VorbisComment));
        assert_eq!(find_channel_mask(&[0, 0, 0]), Err(Error::VorbisComment));
    }
}
