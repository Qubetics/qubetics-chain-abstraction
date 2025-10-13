use crate::database::traits::DBKey;
use crate::database::constants::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConsensusRoundKey {
    pub round: u64,
}
// impl DBKey for ConsensusRoundKey {
//     fn prefix(&self) -> &'static [u8] {
//         CONSENSUS_ROUND_PREFIX
//     }
//     fn key_bytes(&self) -> Vec<u8> {
//         self.round.to_string().as_bytes().to_vec()
//     }
// }

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConsensusResultKey {
    pub round: u64,
}
impl DBKey for ConsensusResultKey {
    fn prefix(&self) -> &'static [u8] {
        CONSENSUS_RESULT_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.round.to_be_bytes().to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SelectedNodesKey {
    pub round: u64,
}
impl DBKey for SelectedNodesKey {
    fn prefix(&self) -> &'static [u8] {
        SELECTED_NODES_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.round.to_be_bytes().to_vec()
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CurrentRoundKey {}
impl DBKey for CurrentRoundKey {
    fn prefix(&self) -> &'static [u8] {
        CURRENT_ROUND_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}



