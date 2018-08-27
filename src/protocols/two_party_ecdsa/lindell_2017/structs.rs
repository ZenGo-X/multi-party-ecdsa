
use cryptography_utils::BigInt;
use cryptography_utils::GE;
use cryptography_utils::FE;

#[derive(Debug, Clone)]
pub enum Visibility {
    Public = 1,
    Private = 2,
}

#[derive(Debug, Clone)]
pub struct WBigInt {
  //  #[serde(with = "serde_bigint")]
    pub val: BigInt,
    pub visibility: Visibility,
}

#[derive(Debug, Clone)]
pub struct WPK {
 //   #[serde(with = "serde_public_key")]
    pub val: GE,
    pub visibility: Visibility,
}

#[derive(Debug, Clone)]
pub struct WSK {
//    #[serde(with = "serde_secret_key")]
    pub val: FE,
    pub visibility: Visibility,
}

#[derive(Debug, Clone)]
pub struct W<T> {
    pub val: T,
    pub visibility: Visibility,
}
