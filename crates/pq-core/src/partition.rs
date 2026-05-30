use crate::{CoreError, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    pub id: usize,
    pub start: usize,
    pub end: usize,
}

impl Partition {
    pub fn new(id: usize, start: usize, end: usize) -> Self {
        Self { id, start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub fn contains(&self, row: usize) -> bool {
        self.start <= row && row < self.end
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionPlan {
    total_rows: usize,
    partitions: Vec<Partition>,
}

impl PartitionPlan {
    pub fn new(total_rows: usize, partitions: Vec<Partition>) -> Result<Self> {
        let partitions = validate_and_sort(total_rows, partitions)?;
        Ok(Self {
            total_rows,
            partitions,
        })
    }

    pub fn balanced(total_rows: usize, shard_count: usize) -> Result<Self> {
        if shard_count == 0 {
            return Err(CoreError::InvalidPartition {
                reason: "shard_count must be positive".to_owned(),
            });
        }
        if total_rows == 0 {
            return Self::new(0, Vec::new());
        }
        if shard_count > total_rows {
            return Err(CoreError::InvalidPartition {
                reason: "shard_count cannot exceed total_rows in the network runtime".to_owned(),
            });
        }

        let base = total_rows / shard_count;
        let remainder = total_rows % shard_count;
        let mut start = 0;
        let mut partitions = Vec::with_capacity(shard_count);

        for id in 0..shard_count {
            let len = base + usize::from(id < remainder);
            let end = start + len;
            partitions.push(Partition::new(id, start, end));
            start = end;
        }

        Self::new(total_rows, partitions)
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }

    pub fn len(&self) -> usize {
        self.partitions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    pub fn owner_of(&self, row: usize) -> Option<usize> {
        self.partitions
            .iter()
            .find(|partition| partition.contains(row))
            .map(|partition| partition.id)
    }

    pub fn validate_coverage(&self) -> Result<()> {
        validate_and_sort(self.total_rows, self.partitions.clone()).map(|_| ())
    }
}

fn validate_and_sort(total_rows: usize, mut partitions: Vec<Partition>) -> Result<Vec<Partition>> {
    partitions.sort_by_key(|partition| (partition.start, partition.end, partition.id));

    if total_rows == 0 {
        if partitions.is_empty() {
            return Ok(partitions);
        }
        return Err(CoreError::InvalidPartition {
            reason: "zero-row plans cannot contain partitions".to_owned(),
        });
    }

    let mut cursor = 0;
    let mut ids = Vec::with_capacity(partitions.len());
    for partition in &partitions {
        if ids.contains(&partition.id) {
            return Err(CoreError::InvalidPartition {
                reason: format!("duplicate partition id {}", partition.id),
            });
        }
        ids.push(partition.id);

        if partition.is_empty() {
            return Err(CoreError::InvalidPartition {
                reason: format!("partition {} is empty", partition.id),
            });
        }
        if partition.end > total_rows {
            return Err(CoreError::InvalidPartition {
                reason: format!(
                    "partition {} ends at {}, beyond total rows {}",
                    partition.id, partition.end, total_rows
                ),
            });
        }
        if partition.start != cursor {
            return Err(CoreError::InvalidPartition {
                reason: format!(
                    "partition {} starts at {}, expected {}",
                    partition.id, partition.start, cursor
                ),
            });
        }
        cursor = partition.end;
    }

    if cursor != total_rows {
        return Err(CoreError::InvalidPartition {
            reason: format!("coverage ends at {cursor}, expected {total_rows}"),
        });
    }

    Ok(partitions)
}
