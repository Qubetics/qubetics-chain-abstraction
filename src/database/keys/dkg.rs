use crate::database::traits::DBKey;
use crate::database::constants::*;





#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgShareKey {
    pub from: String
}
impl DBKey for DkgShareKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_SHARE_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.from.as_bytes().to_vec()
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgCommitmentKey {
    pub from: String
}
impl DBKey for DkgCommitmentKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_COMMITMENT_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.from.as_bytes().to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgValidationKey {
    pub to: String
}
impl DBKey for DkgValidationKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_VALIDATION_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.to.as_bytes().to_vec()
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgFinalSecretKey {
}
impl DBKey for DkgFinalSecretKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_FINAL_SECRET_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgFinalPublicKey {

}

impl DBKey for DkgFinalPublicKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_FINAL_PUBLIC_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgVaultEthAddressKey {
}
impl DBKey for DkgVaultEthAddressKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_VAULT_ETH_ADDRESS_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgVaultBtcAddressKey {
}
impl DBKey for DkgVaultBtcAddressKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_VAULT_BTC_ADDRESS_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgVaultTweakedSecretKey {
}
impl DBKey for DkgVaultTweakedSecretKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_VAULT_TWEAKED_SECRET_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}




#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DkgVaultGroupKey {
}
impl DBKey for DkgVaultGroupKey {
    fn prefix(&self) -> &'static [u8] {
        DKG_VAULT_GROUP_KEY_PREFIX
    }
    fn key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}




