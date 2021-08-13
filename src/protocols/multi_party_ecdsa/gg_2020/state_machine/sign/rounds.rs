use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::BigInt;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, MessageStore, P2PMsgs, Store};
use round_based::Msg;

use crate::utilities::mta::{MessageA, MessageB};

use crate::protocols::multi_party_ecdsa::gg_2020 as gg20;
use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use gg20::party_i::{
    LocalSignature, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use gg20::state_machine::keygen::LocalKey;
use gg20::ErrorType;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GWI(pub GE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GammaI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeltaI(FE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TI(pub GE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TIProof(pub PedersenProof<GE>);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RDash(GE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SI(pub GE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HEGProof(pub HomoELGamalProof<GE>);

pub struct Round0 {
    /// Index of this party
    ///
    /// Must be in range `[0; n)` where `n` is number of parties involved in signing.
    pub i: u16,

    /// List of parties' indexes from keygen protocol
    ///
    /// I.e. `s_l[i]` must be an index of party `i` that was used by this party in keygen protocol.
    // s_l.len()` equals to `n` (number of parties involved in signing)
    pub s_l: Vec<u16>,

    /// Party local secret share
    pub local_key: LocalKey,
}

impl Round0 {
    /// Round 0 initiates two branches of protocol execution: [Round1] and [DecommitRound]. Both of
    /// them should be carried out simultaneously.
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<MessageA>> + Push<Msg<SignBroadcastPhase1>>,
    {
        let sign_keys = SignKeys::create(
            &private_vec[s[i]],
            &self.local_key.vss_scheme.clone(),
            usize::from(self.s_l[usize::from(self.i - 1)]) - 1,
            &self.s_l.iter().map(|&i| usize::from(i) - 1).collect(),
        );
        let (bc1, decom1) = sign_keys.phase1_broadcast();

        let party_ek = self.local_key.paillier_key_vec[usize::from(self.local_key.i - 1)].clone();
        let m_a = MessageA::a(&sign_keys.k_i, &party_ek);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: m_a.0.clone(),
        });

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: bc1.clone(),
        });

        let decom_round = DecommitRound {
            i: self.i,
            com: bc1.clone(),
            decom: decom1.clone(),
        };
        let round1 = Round1 {
            i: self.i,
            s_l: self.s_l.clone(),
            local_key: self.local_key,
            m_a,
            sign_keys,
            decom_round,
        };

        Ok(round1)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    m_a: (MessageA, BigInt),
    sign_keys: SignKeys,
    decom_round: DecommitRound,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input1: BroadcastMsgs<MessageA>,
        input2: BroadcastMsgs<SignBroadcastPhase1>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<(GammaI, WI)>>,
    {
        let m_a_vec = input1.into_vec_including_me(self.m_a.0.clone());
        let bc_vec = input2.into_vec_including_me(self.decom_round.com.clone());

        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        //  let mut beta_randomness_vec = Vec::new();
        //  let mut beta_tag_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        let ttag = self.s_l.len();
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let i = usize::from(self.i - 1);
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = MessageB::b(
                &self.sign_keys.gamma_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].0.clone(),
            );
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &self.sign_keys.w_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].0.clone(),
            );

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            //  beta_randomness_vec.push(beta_randomness);
            //    beta_tag_vec.push(beta_tag);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }

        let party_indices = (1..=self.s_l.len())
            .map(|j| u16::try_from(j).unwrap())
            .filter(|&j| j != self.i);
        for (j, (gamma_i, w_i)) in party_indices.zip(m_b_gamma_vec.zip(m_b_w_vec)) {
            output.push(Msg {
                sender: self.i,
                receiver: Some(j),
                body: (GammaI(gamma_i.clone()), WI(w_i.clone())),
            });
        }

        Ok(Round2 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            beta_vec,
            ni_vec,
            bc_vec,
            m_a_vec,
            decom_round1: self.decom_round,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (
        Store<BroadcastMsgs<(MessageA)>>,
        Store<BroadcastMsgs<(SignBroadcastPhase1)>>,
    ) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round2 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    beta_vec: Vec<FE>,
    ni_vec: Vec<FE>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    decom_round1: DecommitRound,
}

impl Round2 {
    pub fn proceed<O>(self, input_round1: P2PMsgs<(GammaI, WI)>, mut output: O) -> Result<Round3>
    where
        O: Push<Msg<DeltaI>> + Push<Msg<TI>> + Push<Msg<TIProof>>, // TODO: unify TI and TIProof
    {
        let (m_b_gamma_s, m_b_w_s): (Vec<_>, Vec<_>) = input_round1
            .into_vec()
            .into_iter()
            .map(|(gamma_i, w_i)| (gamma_i.0, w_i.0))
            .unzip();

        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let ttag = self.s_l.len();
        let index = usize::from(self.i) - 1;
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let g_w_vec = SignKeys::g_w_vec(
            &self.local_key.pk_vec[..],
            &l_s[..],
            &self.local_key.vss_scheme,
        );
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            let m_b = m_b_gamma_s[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_s[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            assert_eq!(m_b.b_proof.pk, g_w_vec[ind]); //TODO: return error

            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
        }

        let mut delta_i = self.sign_keys.phase2_delta_i(&alpha_vec, &self.beta_vec);

        let mut sigma_i = self.sign_keys.phase2_sigma_i(&miu_vec, &self.ni_vec);
        let (t_i, l_i, t_proof_i) = SignKeys::phase3_compute_t_i(&sigma_i);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: DeltaI(delta_i),
        });
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: TI(t_i),
        });
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: TIProof(t_proof_i),
        });

        Ok(Round3 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: m_b_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            decom_round1: self.decom_round1,
            delta_i,
            t_i,
            l_i,
            sigma_i,
            t_i_proof,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(GammaI, WI)>> {
        (containers::P2PMsgsStore::new(i, n),)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round3 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    mb_gamma_s: Vec<MessageB>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    decom_round1: DecommitRound,
    delta_i: FE,
    t_i: GE,
    l_i: FE,
    sigma_i: FE,
    t_i_proof: PedersenProof<GE>,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input_delta_i: BroadcastMsgs<DeltaI>,
        input_t_i: BroadcastMsgs<TI>,
        input_t_i_proof: BroadcastMsgs<TIProof>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<DecommitRound>>,
    {
        let delta_vec: Vec<_> = input_delta_i
            .into_vec_including_me(DeltaI(self.delta_i))
            .into_iter()
            .map(|DeltaI(delta_i)| delta_i)
            .collect();
        let t_vec: Vec<_> = input_t_i
            .into_vec_including_me(TI(self.t_i))
            .into_iter()
            .map(|TI(t_i)| t_i)
            .collect();
        let t_proof_vec: Vec<_> = input_t_i_proof
            .into_vec_including_me(TIProof(self.t_i_proof))
            .into_iter()
            .map(|TIProof(t_i_proof)| t_i_proof)
            .collect();

        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        let ttag = self.s_l.len();
        for i in 0..ttag {
            PedersenProof::verify(&t_proof_vec[i]).expect("error T proof");
        }

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: self.decom_round1.clone(),
        });

        Ok(Round4 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: self.mb_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            decom_round1: self.decom_round1.clone(),
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            delta_inv,
            t_vec,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (
        Store<BroadcastMsgs<DeltaI>>,
        Store<BroadcastMsgs<TI>>,
        Store<BroadcastMsgs<TIProof>>,
    ) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round4 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    mb_gamma_s: Vec<MessageB>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    decom_round1: DecommitRound,
    t_i: GE,
    l_i: FE,
    sigma_i: FE,
    delta_inv: FE,
    t_vec: Vec<GE>,
}

impl Round4 {
    pub fn proceed<O>(
        self,
        decommit_round1: BroadcastMsgs<DecommitRound>,
        mut output: O,
    ) -> Result<Round5>
    where
        O: Push<Msg<RDash>> + Push<Msg<Vec<PDLwSlackProof>>>,
    {
        let decom_vec: Vec<_> = decommit_round1
            .into_vec_including_me(DecommitRound(self.decom_round1))
            .into_iter()
            .map(|DecomRound| DecomRound.decom)
            .collect();

        let ttag = self.s_l.len();
        let b_proof_vec: Vec<_> = (0..ttag).map(|i| &self.mb_gamma_s[i].b_proof).collect();
        let R = SignKeys::phase4(
            &self.delta_inv,
            &b_proof_vec[..],
            decom_vec.clone(),
            &self.bc_vec,
            i,
        )
        .expect(""); //TODO: propagate the error
        let R_dash = R * self.sign_keys.k_i;

        // each party sends first message to all other parties
        let mut phase5_proofs_vec = Vec::new();
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let index = usize::from(self.i - 1);
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            let proof = LocalSignature::phase5_proof_pdl(
                &R_dash,
                &R,
                &self.m_a.0.c,
                &self.local_key.paillier_key_vec[l_s[index]],
                &self.sign_keys.k_i,
                &self.m_a.1,
                &self.local_key.h1_h2_n_tilde_vec[l_s[ind]],
            );

            phase5_proofs_vec.push(proof);
        }

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: R_dash,
        });

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: phase5_proofs_vec.clone(),
        });

        Ok(Round5 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            t_vec: self.t_vec,
            m_a_vec: self.m_a_vec,
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            R,
            R_dash,
            phase5_proofs_vec,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DecommitRound>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round5 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    t_vec: Vec<GE>,
    m_a_vec: Vec<MessageA>,
    t_i: GE,
    l_i: FE,
    sigma_i: FE,
    R: GE,
    R_dash: GE,
    phase5_proofs_vec: Vec<PDLwSlackProof>,
}

impl Round5 {
    pub fn proceed<O>(
        self,
        R_dash_vec: BroadcastMsgs<RDash>,
        pdl_proof_mat: BroadcastMsgs<Vec<PDLwSlackProof>>,
        mut output: O,
    ) -> Result<CompletedOfflineStage>
    where
        O: Push<Msg<SI>> + Push<Msg<HomoELGamalProof<GE>>>,
    {
        let pdl_proof_mat_inc_me = pdl_proof_mat.into_vec_including_me(self.phase5_proofs_vec);
        let r_dash_vec: Vec<_> = R_dash_vec
            .into_vec_including_me(RDash(self.R_dash))
            .into_iter()
            .map(|RDash| RDash.0)
            .collect();

        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        let ttag = self.s_l.len();
        for i in 0..ttag {
            LocalSignature::phase5_verify_pdl(
                &pdl_proof_mat_inc_me[i],
                &r_dash_vec[i],
                &R,
                &self.m_a_vec[i].c,
                &self.local_key.paillier_key_vec[l_s[i]],
                &self.local_key.h1_h2_n_tilde_vec,
                &l_s,
                i,
            )
            .expect("phase5 verify pdl error");
        }
        LocalSignature::phase5_check_R_dash_sum(&r_dash_vec).expect("R_dash error");

        let (S_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
            &R,
            &self.t_i,
            &self.sigma_i,
            &self.l_i,
        );

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: SI(S_i.clone()),
        });

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: HEGProof(homo_elgamal_proof.clone()),
        });

        Ok(CompletedOfflineStage {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            t_vec: self.t_vec,
            R,
            S_i,
            homo_elgamal_proof,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (
        Store<BroadcastMsgs<RDash>>,
        Store<BroadcastMsgs<Vec<PDLwSlackProof>>>,
    ) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct CompletedOfflineStage {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,
    t_vec: Vec<GE>,
    R: GE,
    S_i: GE,
    homo_elgamal_proof: HomoELGamalProof<GE>,
}

impl CompletedOfflineStage {
    pub fn proceed<O>(
        self,
        SI: BroadcastMsgs<SI>,
        homo_eg_proof: BroadcastMsgs<HEGProof>,
        mut output: O,
    ) {
        let S_i_vec: Vec<_> = SI
            .into_vec_including_me(SI(self.S_i))
            .into_iter()
            .map(|SI| SI.0)
            .collect();
        let hegp_vec: Vec<_> = homo_eg_proof
            .into_vec_including_me(HEGProof(self.homo_elgamal_proof))
            .into_iter()
            .map(|HEGProof| HEGProof.0)
            .collect();
        let R_vec: Vec<_> = (0..self.s_l.len()).map(|_| self.R.clone()).collect();
        LocalSignature::phase6_verify_proof(&S_i_vec, &hegp_vec, &R_vec, &self.t_vec)
            .expect("phase6 verify error");

        LocalSignature::phase6_check_S_i_sum(&self.local_key.y_sum_s, &S_i_vec)
            .expect("phase6 check Si sum error");
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (Store<BroadcastMsgs<SI>>, Store<BroadcastMsgs<HEGProof>>) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }

    pub fn public_key(&self) -> &GE {
        &self.local_key.y_sum_s
    }
}

pub struct Round6 {
    i: u16,
    y_sum: GE,
    // local_signature: LocalSignature,
}

impl Round6 {
    pub fn proceed_manual(self, sigs: Vec<LocalSignature>) -> Result<SignatureRecid> {
        let input = SignStage7Input {
            local_sig_vec: sigs,
            ysum: self.y_sum,
        };

        write_input(self.i, 7, &input);
        let output = sign_stage7(&input)
            .map(|s| s.local_sig)
            .map_err(Error::Round6)?;
        write_output(self.i, 7, &output);

        Ok(output)
    }

    // pub fn proceed(self, input: BroadcastMsgs<LocalSignature>) -> Result<SignatureRecid> {
    //     let sigs = input.into_vec_including_me(self.local_signature.clone());
    //     self.proceed_manual(sigs)
    // }

    // pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<LocalSignature>> {
    //     containers::BroadcastMsgsStore::new(i, n)
    // }

    // pub fn is_expensive(&self) -> bool {
    //     true
    // }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: {0:?}")]
    Round6(ErrorType),
}

/// Round that published decommit message once all commits from all the parties were received
pub struct DecommitRound {
    i: u16,
    com: SignBroadcastPhase1,
    decom: SignDecommitPhase1,
}

/*
impl DecommitRound {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<SignBroadcastPhase1>,
        mut output: O,
    ) -> Result<Commitments>
    where
        O: Push<Msg<SignDecommitPhase1>>,
    {
        let commitments = input.into_vec_including_me(self.com.clone());

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: self.decom,
        });

        Ok(Commitments { commitments })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<SignBroadcastPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
}

 */

/// Produced when [DecommitRound] is finished
pub struct Commitments {
    commitments: Vec<SignBroadcastPhase1>,
}

#[cfg(test)]
fn write_input<T: Serialize>(party_i: u16, stage: u16, input: &T) {
    if let Some(file_name) = std::env::var_os("WRITE_FILE") {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut json_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .unwrap();
        writeln!(json_file, "Party {} stage {} input:", party_i, stage).unwrap();
        writeln!(
            json_file,
            "{}",
            serde_json::to_string_pretty(input).unwrap()
        )
        .unwrap();
    }
}
#[cfg(test)]
fn write_output<T: Serialize>(party_i: u16, stage: u16, output: &T) {
    if let Some(file_name) = std::env::var_os("WRITE_FILE") {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut json_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .unwrap();
        writeln!(json_file, "Party {} stage {} output:", party_i, stage).unwrap();
        writeln!(
            json_file,
            "{}",
            serde_json::to_string_pretty(output).unwrap()
        )
        .unwrap();
    }
}
#[cfg(not(test))]
fn write_input<T: Serialize>(_party_i: u16, _stage: u16, _input: &T) {}
#[cfg(not(test))]
fn write_output<T: Serialize>(_party_i: u16, _stage: u16, _output: &T) {}
