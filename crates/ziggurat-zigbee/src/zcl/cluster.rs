//! The server side of a cluster: its attributes and commands.
//!
//! A cluster supplies only its own attributes and commands through [`ClusterServer`].
//! The behavior the global commands share across clusters lives here: the
//! ClusterRevision attribute, the access and data type checks, the order of the write
//! checks, and fitting records into the response frame.

use alloc::vec::Vec;
use core::fmt::Debug;
use ziggurat_ieee_802154::{FrameWriter, write_frame};

use super::foundation::{
    AttributeInformation, DiscoverAttributes, DiscoverAttributesResponse,
    ReadAttributeStatusRecord, ReadAttributes, Status, WriteAttributeRecord,
    WriteAttributeStatusRecord, WriteAttributes, WriteAttributesResponse,
};
use super::types::{AttributeValue, DataType};
use crate::Instant;
use crate::aps::frame::MAX_ASDU_SIZE;

/// ZCL 2.3.4.5.1: the global attribute every cluster has.
pub const CLUSTER_REVISION_ATTRIBUTE_ID: u16 = 0xFFFD;

/// ZCL 2.3.4.4: whether an attribute can be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSpec {
    pub id: u16,
    pub data_type: DataType,
    pub access: Access,
}

/// What a cluster-specific command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Carried out with no response of its own: a Default Response reports SUCCESS if
    /// the sender asked for one.
    Done,
    /// Carried out, answered with a cluster-specific response command.
    Respond { command_id: u8, payload: Vec<u8> },
    /// Not carried out: a Default Response reports the status.
    Failed(Status),
}

/// A cluster's server side. Methods take the current time, for clusters whose state
/// changes over time; a cluster never reads a clock.
pub trait ClusterServer: Debug + Send {
    fn cluster_id(&self) -> u16;

    /// The value of the ClusterRevision attribute.
    fn revision(&self) -> u16;

    /// The cluster's own attributes. ClusterRevision is added for every cluster.
    fn attributes(&self) -> &[AttributeSpec];

    /// The current value of one of [`Self::attributes`], of its declared type.
    fn read(&self, attribute_id: u16, now: Instant) -> AttributeValue;

    /// Check a write to a writable attribute, of its declared type, before any write
    /// happens: INVALID_VALUE for a value out of range, NOT_AUTHORIZED when writes are
    /// not accepted now.
    fn validate(&self, _attribute_id: u16, _value: &AttributeValue) -> Result<(), Status> {
        Ok(())
    }

    /// Write a value that passed [`Self::validate`].
    fn write(&mut self, attribute_id: u16, _value: AttributeValue, _now: Instant) {
        unreachable!(
            "cluster {:#06x} declares attribute {attribute_id:#06x} writable but cannot write it",
            self.cluster_id()
        )
    }

    /// Carry out a cluster-specific command sent to the server.
    fn command(&mut self, _command_id: u8, _payload: &[u8], _now: Instant) -> CommandOutcome {
        CommandOutcome::Failed(Status::UnsupCommand)
    }
}

fn attribute_spec(cluster: &dyn ClusterServer, attribute_id: u16) -> Option<AttributeSpec> {
    if attribute_id == CLUSTER_REVISION_ATTRIBUTE_ID {
        return Some(AttributeSpec {
            id: CLUSTER_REVISION_ATTRIBUTE_ID,
            data_type: DataType::Uint16,
            access: Access::Read,
        });
    }

    cluster
        .attributes()
        .iter()
        .find(|spec| spec.id == attribute_id)
        .copied()
}

fn read_attribute(
    cluster: &dyn ClusterServer,
    attribute_id: u16,
    now: Instant,
) -> Result<AttributeValue, Status> {
    if attribute_id == CLUSTER_REVISION_ATTRIBUTE_ID {
        return Ok(AttributeValue::Uint16(cluster.revision()));
    }

    attribute_spec(cluster, attribute_id)
        .map(|spec| cluster.read(spec.id, now))
        .ok_or(Status::UnsupportedAttribute)
}

/// ZCL 2.5.1.3: write a status record for each requested attribute. A record that
/// does not fit is replaced by an INSUFFICIENT_SPACE record; when that does not fit
/// either, the response ends there.
pub fn read_attributes(
    cluster: &dyn ClusterServer,
    request: &ReadAttributes,
    now: Instant,
    writer: &mut FrameWriter,
) {
    for &attribute_id in &request.attribute_ids {
        let record = ReadAttributeStatusRecord {
            attribute_id,
            result: read_attribute(cluster, attribute_id, now),
        };

        if append_record(writer, &record) {
            continue;
        }

        let record = ReadAttributeStatusRecord {
            attribute_id,
            result: Err(Status::InsufficientSpace),
        };

        if !append_record(writer, &record) {
            return;
        }
    }
}

/// Append a whole record or nothing: a record that does not fit leaves no partial
/// bytes behind.
fn append_record(writer: &mut FrameWriter, record: &ReadAttributeStatusRecord) -> bool {
    write_frame::<MAX_ASDU_SIZE>(|record_writer| record.serialize(record_writer))
        .is_ok_and(|bytes| writer.extend(&bytes).is_ok())
}

/// ZCL 2.5.3.3: the checks of one write record, in the order the spec lists them.
fn check_write(cluster: &dyn ClusterServer, record: &WriteAttributeRecord) -> Result<(), Status> {
    let spec = attribute_spec(cluster, record.attribute_id).ok_or(Status::UnsupportedAttribute)?;

    if record.value.data_type() != spec.data_type {
        return Err(Status::InvalidDataType);
    }

    if spec.access == Access::Read {
        return Err(Status::ReadOnly);
    }

    cluster.validate(record.attribute_id, &record.value)
}

/// ZCL 2.5.3.3: write every record that passes its checks.
pub fn write_attributes(
    cluster: &mut dyn ClusterServer,
    request: WriteAttributes,
    now: Instant,
) -> WriteAttributesResponse {
    let mut failures = Vec::new();

    for record in request.records {
        match check_write(cluster, &record) {
            Ok(()) => cluster.write(record.attribute_id, record.value, now),
            Err(status) => failures.push(WriteAttributeStatusRecord {
                status,
                attribute_id: record.attribute_id,
            }),
        }
    }

    WriteAttributesResponse { failures }
}

/// ZCL 2.5.4: write every record only if all of them pass their checks.
pub fn write_attributes_undivided(
    cluster: &mut dyn ClusterServer,
    request: WriteAttributes,
    now: Instant,
) -> WriteAttributesResponse {
    let failures: Vec<WriteAttributeStatusRecord> = request
        .records
        .iter()
        .filter_map(|record| {
            check_write(cluster, record)
                .err()
                .map(|status| WriteAttributeStatusRecord {
                    status,
                    attribute_id: record.attribute_id,
                })
        })
        .collect();

    if failures.is_empty() {
        for record in request.records {
            cluster.write(record.attribute_id, record.value, now);
        }
    }

    WriteAttributesResponse { failures }
}

/// ZCL 2.5.6.3: write every record that passes its checks, and skip the others.
pub fn write_attributes_no_response(
    cluster: &mut dyn ClusterServer,
    request: WriteAttributes,
    now: Instant,
) {
    for record in request.records {
        if check_write(cluster, &record).is_ok() {
            cluster.write(record.attribute_id, record.value, now);
        }
    }
}

/// ZCL 2.5.13.3: the attributes from the start identifier on, in ascending order,
/// as many as the request and the frame allow.
pub fn discover_attributes(
    cluster: &dyn ClusterServer,
    request: &DiscoverAttributes,
    writer: &FrameWriter,
) -> DiscoverAttributesResponse {
    // The discovery complete flag takes one byte, each record three
    let room = writer.remaining().saturating_sub(1) / 3;
    let limit = room.min(usize::from(request.maximum_attribute_ids));

    let mut ids: Vec<u16> = cluster
        .attributes()
        .iter()
        .map(|spec| spec.id)
        .chain([CLUSTER_REVISION_ATTRIBUTE_ID])
        .filter(|&id| id >= request.start_attribute_id)
        .collect();
    ids.sort_unstable();

    let attributes = ids
        .iter()
        .take(limit)
        .map(|&id| AttributeInformation {
            attribute_id: id,
            data_type: attribute_spec(cluster, id)
                .expect("the identifier came from the cluster")
                .data_type,
        })
        .collect();

    DiscoverAttributesResponse {
        discovery_complete: ids.len() <= limit,
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// 0x0000 is a read-only uint8 of 7, 0x0001 a writable uint16 up to 100, 0x0002 a
    /// read-only 20-byte string.
    #[derive(Debug, Default)]
    struct TestCluster {
        writable: u16,
    }

    const ATTRIBUTES: [AttributeSpec; 3] = [
        AttributeSpec {
            id: 0x0000,
            data_type: DataType::Uint8,
            access: Access::Read,
        },
        AttributeSpec {
            id: 0x0001,
            data_type: DataType::Uint16,
            access: Access::ReadWrite,
        },
        AttributeSpec {
            id: 0x0002,
            data_type: DataType::CharacterString,
            access: Access::Read,
        },
    ];

    impl ClusterServer for TestCluster {
        fn cluster_id(&self) -> u16 {
            0xFC00
        }

        fn revision(&self) -> u16 {
            1
        }

        fn attributes(&self) -> &[AttributeSpec] {
            &ATTRIBUTES
        }

        fn read(&self, attribute_id: u16, _now: Instant) -> AttributeValue {
            match attribute_id {
                0x0000 => AttributeValue::Uint8(7),
                0x0001 => AttributeValue::Uint16(self.writable),
                _ => AttributeValue::CharacterString(Some(vec![b'x'; 20])),
            }
        }

        fn validate(&self, _attribute_id: u16, value: &AttributeValue) -> Result<(), Status> {
            match value {
                AttributeValue::Uint16(value) if *value > 100 => Err(Status::InvalidValue),
                _ => Ok(()),
            }
        }

        fn write(&mut self, _attribute_id: u16, value: AttributeValue, _now: Instant) {
            let AttributeValue::Uint16(value) = value else {
                unreachable!()
            };
            self.writable = value;
        }
    }

    #[test]
    fn read_attributes_falls_back_to_insufficient_space_then_stops() {
        let mut buffer = heapless::Vec::<u8, 10>::new();
        let mut writer = FrameWriter::new(&mut buffer, 10);

        let request = ReadAttributes {
            attribute_ids: vec![0x0000, 0x0002, 0x0003],
        };
        read_attributes(
            &TestCluster::default(),
            &request,
            Instant::from_micros(0),
            &mut writer,
        );

        assert_eq!(
            writer.written(),
            [
                // 0x0000: SUCCESS, uint8, 7
                0x00, 0x00, 0x00, 0x20, 0x07, // 0x0002 does not fit: INSUFFICIENT_SPACE
                0x02, 0x00,
                0x89,
                // 0x0003 does not fit even as a status record: the response ends
            ]
        );
    }

    #[test]
    fn write_checks_run_in_spec_order_and_undivided_writes_all_or_nothing() {
        let mut cluster = TestCluster::default();
        let record = |attribute_id, value| WriteAttributeRecord {
            attribute_id,
            value,
        };
        let failure = |status, attribute_id| WriteAttributeStatusRecord {
            status,
            attribute_id,
        };

        let response = write_attributes(
            &mut cluster,
            WriteAttributes {
                records: vec![
                    record(0x0009, AttributeValue::Uint8(1)),
                    // A wrong data type is reported before read-only or range
                    record(0x0000, AttributeValue::Uint16(1)),
                    record(0x0000, AttributeValue::Uint8(1)),
                    record(0x0001, AttributeValue::Uint16(200)),
                    record(0x0001, AttributeValue::Uint16(50)),
                ],
            },
            Instant::from_micros(0),
        );
        assert_eq!(
            response.failures,
            [
                failure(Status::UnsupportedAttribute, 0x0009),
                failure(Status::InvalidDataType, 0x0000),
                failure(Status::ReadOnly, 0x0000),
                failure(Status::InvalidValue, 0x0001),
            ]
        );
        assert_eq!(cluster.writable, 50);

        // One failing record keeps the others from being written
        let response = write_attributes_undivided(
            &mut cluster,
            WriteAttributes {
                records: vec![
                    record(0x0001, AttributeValue::Uint16(60)),
                    record(0x0000, AttributeValue::Uint8(1)),
                ],
            },
            Instant::from_micros(0),
        );
        assert_eq!(response.failures, [failure(Status::ReadOnly, 0x0000)]);
        assert_eq!(cluster.writable, 50);
    }
}
