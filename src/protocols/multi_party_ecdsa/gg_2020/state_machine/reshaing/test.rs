#[cfg(test)]
mod tests {
    use crate::protocols::multi_party_ecdsa::gg_2020::party_i::verify;
    use crate::protocols::multi_party_ecdsa::gg_2020::party_i::Keys;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey};
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::refresh_message::RefreshMessage;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::M_SECURITY;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
        CompletedOfflineStage, OfflineStage, SignManual,
    };
    use curv::arithmetic::Converter;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
        ShamirSecretSharing, VerifiableSS,
    };

    use curv::elliptic::curves::Secp256k1;
    use curv::BigInt;

    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::add_party_message::JoinMessage;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::error::FsDkrResult;
    use paillier::DecryptionKey;
    use round_based::dev::Simulation;
    use sha2::Digest;
    use sha2::Sha256;
    use std::collections::HashMap;

    #[test]
    fn test1() {
        //simulate keygen
        let t = 3;
        let n = 6;
        let mut keys = simulate_keygen(t, n);

        let old_keys = keys.clone();
        simulate_dkr::<{ M_SECURITY }>(&mut keys);

        // check that sum of old keys is equal to sum of new keys
        let old_linear_secret_key: Vec<_> = (0..old_keys.len())
            .map(|i| old_keys[i].keys_linear.x_i.clone())
            .collect();

        let new_linear_secret_key: Vec<_> = (0..keys.len())
            .map(|i| keys[i].keys_linear.x_i.clone())
            .collect();
        let indices: Vec<_> = (0..(t + 1) as u16).collect();
        let vss = VerifiableSS::<Secp256k1> {
            parameters: ShamirSecretSharing {
                threshold: t,
                share_count: n,
            },
            commitments: Vec::new(),
        };
        assert_eq!(
            vss.reconstruct(&indices[..], &old_linear_secret_key[0..(t + 1) as usize]),
            vss.reconstruct(&indices[..], &new_linear_secret_key[0..(t + 1) as usize])
        );
        assert_ne!(old_linear_secret_key, new_linear_secret_key);
    }

    #[test]
    fn test_sign_rotate_sign() {
        let mut keys = simulate_keygen(2, 5);
        let offline_sign = simulate_offline_stage(keys.clone(), &[1, 2, 3]);
        simulate_signing(offline_sign, b"ZenGo");
        simulate_dkr::<{ M_SECURITY }>(&mut keys);
        let offline_sign = simulate_offline_stage(keys.clone(), &[2, 3, 4]);
        simulate_signing(offline_sign, b"ZenGo");
        simulate_dkr::<{ M_SECURITY }>(&mut keys);
        let offline_sign = simulate_offline_stage(keys, &[1, 3, 5]);
        simulate_signing(offline_sign, b"ZenGo");
    }

    #[test]
    fn test_remove_sign_rotate_sign() {
        let mut keys = simulate_keygen(2, 5);
        let offline_sign = simulate_offline_stage(keys.clone(), &[1, 2, 3]);
        simulate_signing(offline_sign, b"ZenGo");
        simulate_dkr_removal::<{ M_SECURITY }>(&mut keys, [1].to_vec());
        let offline_sign = simulate_offline_stage(keys.clone(), &[2, 3, 4]);
        simulate_signing(offline_sign, b"ZenGo");
        simulate_dkr_removal::<{ M_SECURITY }>(&mut keys, [1, 2].to_vec());
        let offline_sign = simulate_offline_stage(keys, &[3, 4, 5]);
        simulate_signing(offline_sign, b"ZenGo");
    }

    #[test]
    fn test_add_party_with_permute() {
        fn simulate_replace<const M: usize>(
            keys: &mut Vec<LocalKey<Secp256k1>>,
            party_indices: &[u16],
            old_to_new_map: &HashMap<u16, u16>,
            t: u16,
            n: u16,
        ) -> FsDkrResult<()> {
            fn generate_join_messages_and_keys<const M: usize>(
                number_of_new_parties: usize,
            ) -> (Vec<JoinMessage<Secp256k1, Sha256, M>>, Vec<Keys>) {
                // the new party generates it's join message to start joining the computation
                (0..number_of_new_parties)
                    .map(|_| JoinMessage::distribute())
                    .unzip()
            }

            fn generate_refresh_parties_replace<const M: usize>(
                keys: &mut [LocalKey<Secp256k1>],
                old_to_new_map: &HashMap<u16, u16>,
                join_messages: &[JoinMessage<Secp256k1, Sha256, M>],
            ) -> (
                Vec<RefreshMessage<Secp256k1, Sha256, M>>,
                Vec<DecryptionKey>,
            ) {
                let new_n = (&keys.len() + join_messages.len()) as u16;
                keys.iter_mut()
                    .map(|key| {
                        RefreshMessage::replace(join_messages, key, old_to_new_map, new_n).unwrap()
                    })
                    .unzip()
            }

            // each party that wants to join generates a join message and a pair of paillier keys.
            let (mut join_messages, new_keys) =
                generate_join_messages_and_keys::<{ M_SECURITY }>(party_indices.len());

            // each new party has to be informed through offchannel communication what party index
            // it has been assigned (the information is public).
            for (join_message, party_index) in join_messages.iter_mut().zip(party_indices) {
                join_message.party_index = Some(*party_index);
            }

            // each existing party has to generate it's refresh message aware of the new parties
            let (refresh_messages, dk_keys) =
                generate_refresh_parties_replace(keys, &old_to_new_map, join_messages.as_slice());
            let mut new_keys_vec: Vec<(u16, LocalKey<Secp256k1>)> =
                Vec::with_capacity(keys.len() + join_messages.len());
            // all existing parties rotate aware of the join_messages
            for i in 0..keys.len() as usize {
                RefreshMessage::collect(
                    refresh_messages.as_slice(),
                    &mut keys[i],
                    dk_keys[i].clone(),
                    join_messages.as_slice(),
                )
                .expect("");
                new_keys_vec.push((keys[i].i - 1, keys[i].clone()));
            }

            // all new parties generate a local key
            for (join_message, dk) in join_messages.iter().zip(new_keys) {
                let party_index = join_message.party_index.unwrap();
                let local_key = join_message.collect(
                    refresh_messages.as_slice(),
                    dk,
                    join_messages.as_slice(),
                    t,
                    n,
                )?;

                new_keys_vec.push((party_index - 1, local_key));
            }

            new_keys_vec.sort_by(|a, b| a.0.cmp(&b.0));
            let keys_replacements = new_keys_vec
                .iter()
                .map(|a| a.1.clone())
                .collect::<Vec<LocalKey<Secp256k1>>>();
            *keys = keys_replacements;
            Ok(())
        }

        let t = 2;
        let n = 7;

        let all_keys = simulate_keygen(t, n);
        // Remove the 2nd and 7th party
        let mut keys = all_keys.clone();
        keys.remove(6);
        keys.remove(1);

        let mut old_to_new_map: HashMap<u16, u16> = HashMap::new();
        old_to_new_map.insert(1, 4);
        old_to_new_map.insert(3, 1);
        old_to_new_map.insert(4, 3);
        old_to_new_map.insert(5, 6);
        old_to_new_map.insert(6, 5);

        // Simulate the replace
        simulate_replace::<{ M_SECURITY }>(&mut keys, &[2, 7], &old_to_new_map, t, n).unwrap();
        // check that sum of old keys is equal to sum of new keys
        let old_linear_secret_key: Vec<_> = (0..all_keys.len())
            .map(|i| all_keys[i].keys_linear.x_i.clone())
            .collect();

        let new_linear_secret_key: Vec<_> = (0..keys.len())
            .map(|i| keys[i].keys_linear.x_i.clone())
            .collect();
        let indices: Vec<_> = (0..(t + 1) as u16).collect();
        let vss = VerifiableSS::<Secp256k1> {
            parameters: ShamirSecretSharing {
                threshold: t,
                share_count: n,
            },
            commitments: Vec::new(),
        };
        assert_eq!(
            vss.reconstruct(&indices[..], &old_linear_secret_key[0..(t + 1) as usize]),
            vss.reconstruct(&indices[..], &new_linear_secret_key[0..(t + 1) as usize])
        );
        assert_ne!(old_linear_secret_key, new_linear_secret_key);

        let offline_sign = simulate_offline_stage(keys, &[1, 2, 7]);
        simulate_signing(offline_sign, b"ZenGo");
    }

    fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey<Secp256k1>> {
        //simulate keygen
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(false);

        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }

        simulation.run().unwrap()
    }

    fn simulate_dkr_removal<const M: usize>(
        keys: &mut Vec<LocalKey<Secp256k1>>,
        remove_party_indices: Vec<u16>,
    ) {
        let mut broadcast_messages: HashMap<usize, Vec<RefreshMessage<Secp256k1, Sha256, M>>> =
            HashMap::new();
        let mut new_dks: HashMap<usize, DecryptionKey> = HashMap::new();
        let mut refresh_messages: Vec<RefreshMessage<Secp256k1, Sha256, M>> = Vec::new();
        let mut party_key: HashMap<usize, LocalKey<Secp256k1>> = HashMap::new();
        // TODO: Verify this is correct
        let new_n = keys.len() as u16;
        for key in keys.iter_mut() {
            let (refresh_message, new_dk) = RefreshMessage::distribute(key.i, key, new_n).unwrap();
            refresh_messages.push(refresh_message.clone());
            new_dks.insert(refresh_message.party_index.into(), new_dk);
            party_key.insert(refresh_message.party_index.into(), key.clone());
        }

        for refresh_message in refresh_messages.iter() {
            broadcast_messages.insert(refresh_message.party_index.into(), Vec::new());
        }

        for refresh_message in refresh_messages.iter_mut() {
            if !remove_party_indices.contains(&refresh_message.party_index.into()) {
                refresh_message.remove_party_indices = remove_party_indices.clone();
            } else {
                let mut new_remove_party_indices = remove_party_indices.clone();
                new_remove_party_indices.retain(|value| *value != refresh_message.party_index);
                refresh_message.remove_party_indices = new_remove_party_indices;
            }

            for (party_index, refresh_bucket) in broadcast_messages.iter_mut() {
                if refresh_message
                    .remove_party_indices
                    .contains(&(*party_index as u16))
                {
                    continue;
                }
                refresh_bucket.push(refresh_message.clone());
            }
        }

        for remove_party_index in remove_party_indices.iter() {
            assert_eq!(broadcast_messages[&(*remove_party_index as usize)].len(), 1);
        }

        // keys will be updated to refreshed values
        for (party, key) in party_key.iter_mut() {
            if remove_party_indices.contains(&(*party as u16)) {
                continue;
            }

            RefreshMessage::collect(
                broadcast_messages[party].clone().as_slice(),
                key,
                new_dks[party].clone(),
                &[],
            )
            .expect("");
        }

        for remove_party_index in remove_party_indices {
            let result = RefreshMessage::collect(
                &broadcast_messages[&(remove_party_index as usize)],
                &mut keys[remove_party_index as usize],
                new_dks[&(remove_party_index as usize)].clone(),
                &[],
            );
            assert!(result.is_err());
        }
    }

    fn simulate_dkr<const M: usize>(
        keys: &mut Vec<LocalKey<Secp256k1>>,
    ) -> (
        Vec<RefreshMessage<Secp256k1, Sha256, M>>,
        Vec<DecryptionKey>,
    ) {
        let mut broadcast_vec: Vec<RefreshMessage<Secp256k1, Sha256, M>> = Vec::new();
        let mut new_dks: Vec<DecryptionKey> = Vec::new();
        let keys_len = keys.len();
        for key in keys.iter_mut() {
            let (refresh_message, new_dk) =
                RefreshMessage::distribute(key.i, key, keys_len as u16).unwrap();
            broadcast_vec.push(refresh_message);
            new_dks.push(new_dk);
        }

        // keys will be updated to refreshed values
        for i in 0..keys.len() as usize {
            RefreshMessage::collect(&broadcast_vec, &mut keys[i], new_dks[i].clone(), &[])
                .expect("");
        }

        (broadcast_vec, new_dks)
    }

    fn simulate_offline_stage(
        local_keys: Vec<LocalKey<Secp256k1>>,
        s_l: &[u16],
    ) -> Vec<CompletedOfflineStage> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(false);

        for (i, &keygen_i) in (1..).zip(s_l) {
            simulation.add_party(
                OfflineStage::new(
                    i,
                    s_l.to_vec(),
                    local_keys[usize::from(keygen_i - 1)].clone(),
                )
                .unwrap(),
            );
        }

        simulation.run().unwrap()
    }

    fn simulate_signing(offline: Vec<CompletedOfflineStage>, message: &[u8]) {
        let message = create_hash(&[&BigInt::from_bytes(message)]);
        let pk = &offline[0].public_key();

        let parties = offline
            .iter()
            .map(|o| SignManual::new(message.clone(), o.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (parties, local_sigs): (Vec<_>, Vec<_>) = parties.into_iter().unzip();
        // parties.remove(0).complete(&local_sigs[1..]).unwrap();
        let local_sigs_except = |i: usize| {
            let mut v = vec![];
            v.extend_from_slice(&local_sigs[..i]);
            if i + 1 < local_sigs.len() {
                v.extend_from_slice(&local_sigs[i + 1..]);
            }
            v
        };

        assert!(parties
            .into_iter()
            .enumerate()
            .map(|(i, p)| p.complete(&local_sigs_except(i)).unwrap())
            .all(|signature| verify(&signature, &pk, &message).is_ok()));
    }

    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let hasher = Sha256::new();

        for value in big_ints {
            hasher.clone().chain(&BigInt::to_bytes(value));
        }

        let result_hex = hasher.finalize();
        BigInt::from_bytes(&result_hex[..])
    }
}
