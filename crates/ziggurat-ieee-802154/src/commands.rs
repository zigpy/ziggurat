#![allow(clippy::useless_conversion)]

use crate::types::Nwk;
use crate::{Ieee802154AssociationStatus, Ieee802154CommandId, Ieee802154DisassociationReason};
use abstract_bits::{AbstractBits, abstract_bits};

/// 802.15.4 Association Request Command
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[abstract_bits(bits = 1)]
#[repr(u8)]
pub enum AssociationRequestDeviceType {
    ReducedFunctionDevice = 0b0,
    FullFunctionDevice = 0b1,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[abstract_bits(bits = 1)]
#[repr(u8)]
pub enum AssociationRequestPowerSource {
    BatteryPower = 0b0,
    MainsPower = 0b1,
}

#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154AssociationRequestCommand {
    pub alternate_pan_coordinator: bool,
    pub device_type: AssociationRequestDeviceType,
    pub power_source: AssociationRequestPowerSource,
    pub receive_on_when_idle: bool,
    pub reserved1: u2,
    pub security_capable: bool,
    pub allocate_address: bool,
}

impl Ieee802154Command for Ieee802154AssociationRequestCommand {
    const COMMAND_ID: Ieee802154CommandId = Ieee802154CommandId::AssociationRequest;
}

/// 802.15.4 Association Response Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154AssociationResponseCommand {
    pub short_address: Nwk,
    pub association_status: Ieee802154AssociationStatus,
}

impl Ieee802154Command for Ieee802154AssociationResponseCommand {
    const COMMAND_ID: Ieee802154CommandId = Ieee802154CommandId::AssociationResponse;
}

/// 802.15.4 Disassociation Notification Command
#[abstract_bits]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154DisassociationNotificationCommand {
    pub disassociation_reason: Ieee802154DisassociationReason,
}

impl Ieee802154Command for Ieee802154DisassociationNotificationCommand {
    const COMMAND_ID: Ieee802154CommandId = Ieee802154CommandId::DisassociationNotification;
}

/// 802.15.4 Data Request Command (no payload)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154DataRequestCommand;

impl AbstractBits for Ieee802154DataRequestCommand {
    const MIN_BITS: usize = 0;
    const MAX_BITS: usize = 0;

    fn read_abstract_bits(
        _reader: &mut abstract_bits::BitReader,
    ) -> Result<Self, abstract_bits::FromBytesError> {
        Ok(Self)
    }

    fn write_abstract_bits(
        &self,
        _writer: &mut abstract_bits::BitWriter,
    ) -> Result<(), abstract_bits::ToBytesError> {
        Ok(())
    }
}

impl Ieee802154Command for Ieee802154DataRequestCommand {
    const COMMAND_ID: Ieee802154CommandId = Ieee802154CommandId::DataRequest;
}

/// 802.15.4 Beacon Request Command (no payload)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ieee802154BeaconRequestCommand;

impl AbstractBits for Ieee802154BeaconRequestCommand {
    const MIN_BITS: usize = 0;
    const MAX_BITS: usize = 0;

    fn read_abstract_bits(
        _reader: &mut abstract_bits::BitReader,
    ) -> Result<Self, abstract_bits::FromBytesError> {
        Ok(Self)
    }

    fn write_abstract_bits(
        &self,
        _writer: &mut abstract_bits::BitWriter,
    ) -> Result<(), abstract_bits::ToBytesError> {
        Ok(())
    }
}

impl Ieee802154Command for Ieee802154BeaconRequestCommand {
    const COMMAND_ID: Ieee802154CommandId = Ieee802154CommandId::BeaconRequest;
}

/// Trait for 802.15.4 MAC commands
pub trait Ieee802154Command: abstract_bits::AbstractBits + Sized {
    const COMMAND_ID: Ieee802154CommandId;

    fn serialize(&self) -> Result<Vec<u8>, crate::SerializeError> {
        crate::serialize_command(self, Self::COMMAND_ID)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, crate::DeserializeError> {
        crate::deserialize_command(bytes, Self::COMMAND_ID)
    }
}
