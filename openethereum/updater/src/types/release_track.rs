// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Open Ethereum.

// Open Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Open Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Open Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! Types used in the public API

use std::fmt;

/// A release's track.
#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ReleaseTrack {
	/// Stable track.
	Stable = 1,
	/// Nightly track.
	Nightly = 2,
	/// No known track, also "current executable's track" when it's not yet known.
	Unknown = 0,
}

impl fmt::Display for ReleaseTrack {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", match *self {
			ReleaseTrack::Stable => "stable",
			ReleaseTrack::Nightly => "nightly",
			ReleaseTrack::Unknown => "unknown",
		})
	}
}

impl<'a> From<&'a str> for ReleaseTrack {
	fn from(s: &'a str) -> Self {
		match s {
			"stable" => ReleaseTrack::Stable,
			"nightly" => ReleaseTrack::Nightly,
			_ => ReleaseTrack::Unknown,
		}
	}
}

impl From<u8> for ReleaseTrack {
	fn from(i: u8) -> Self {
		match i {
			1 => ReleaseTrack::Stable,
			2 => ReleaseTrack::Nightly,
			_ => ReleaseTrack::Unknown,
		}
	}
}

impl From<ReleaseTrack> for u8 {
	fn from(rt: ReleaseTrack) -> Self {
		rt as u8
	}
}

#[cfg(test)]
mod tests {
	use super::ReleaseTrack;

	#[test]
	fn test_release_track_from() {
		assert_eq!(ReleaseTrack::Stable, 1u8.into());
		assert_eq!(ReleaseTrack::Nightly, 2u8.into());
		assert_eq!(ReleaseTrack::Unknown, 0u8.into());
	}

	#[test]
	fn test_release_track_into() {
		assert_eq!(1u8, u8::from(ReleaseTrack::Stable));
		assert_eq!(2u8, u8::from(ReleaseTrack::Nightly));
		assert_eq!(0u8, u8::from(ReleaseTrack::Unknown));
	}

	#[test]
	fn test_release_track_from_str() {
		assert_eq!(ReleaseTrack::Stable, "stable".into());
		assert_eq!(ReleaseTrack::Nightly, "nightly".into());
		assert_eq!(ReleaseTrack::Unknown, "unknown".into());
	}

	#[test]
	fn test_release_track_into_str() {
		assert_eq!("stable", ReleaseTrack::Stable.to_string());
		assert_eq!("nightly", ReleaseTrack::Nightly.to_string());
		assert_eq!("unknown", ReleaseTrack::Unknown.to_string());
	}
}
