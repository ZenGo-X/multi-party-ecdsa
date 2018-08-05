use cryptography_utils::arithmetic::serde::serde_bigint;
use cryptography_utils::elliptic::curves::serde::{serde_public_key, serde_secret_key};
use cryptography_utils::BigInt;
use cryptography_utils::PK;
use cryptography_utils::SK;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Visibility {
    Public = 1,
    Private = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WBigInt {
    #[serde(with = "serde_bigint")]
    pub val: BigInt,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPK {
    #[serde(with = "serde_public_key")]
    pub val: PK,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WSK {
    #[serde(with = "serde_secret_key")]
    pub val: SK,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W<T> {
    pub val: T,
    pub visibility: Visibility,
}
