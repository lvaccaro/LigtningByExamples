// Submarine swap

// Alice = user: pay merchant in onchain btc
// Bob = swapper: swap btc <-> lightning btc
// Charlie = merchant: receive lightning btc

// 1. Charlie generates an invoice for the selected amount
// 2. Charlie sends ln invoice to Bob (get payment_hash)
// 3. Alice pays htlc generate with the spending policy
// 4. Bob pays Charlie ln invoice (get payment_preimage)
// 5. Bob sign htlc with preimage to unlock funds

extern crate lightningd;
extern crate bitcoind;
extern crate miniscript;
extern crate hex;
extern crate base64;

use std::{
    thread,
    time::Duration,
};
use std::str;
use std::str::FromStr;
use lightningd::LightningD;
use clightningrpc::lightningrpc::PayOptions;
use clightningrpc::requests;

use bitcoind::BitcoinD;
use bitcoind::exe_path;
use bitcoind::bitcoincore_rpc::json;
use bitcoind::bitcoincore_rpc::bitcoin::Address;
use bitcoind::bitcoincore_rpc::{ Auth, Client, RpcApi};

use miniscript::bitcoin;
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::secp256k1;
use miniscript::bitcoin::{ Network, Amount };
use miniscript::policy::Concrete;
use miniscript::Descriptor;
use miniscript::psbt::PsbtExt;
use miniscript::bitcoin::sighash::SighashCache;
use miniscript::bitcoin::{OutPoint, Transaction, TxIn, TxOut, Txid, ScriptBuf};
use miniscript::bitcoin::hashes::sha256;

fn create_wallet(bitcoind: &BitcoinD, label: &str, disable_private_keys: bool) -> Client {
    bitcoind.client.create_wallet(label, Some(disable_private_keys), None, None, None).unwrap();
    Client::new(
        &bitcoind.rpc_url_with_wallet(label),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    ).unwrap()
}

fn btc<F: Into<f64>>(btc: F) -> Amount {
    Amount::from_btc(btc.into()).unwrap()
}

// Find the Outpoint by spk
fn get_vout(cl: &Client, txid: Txid, value: Amount, spk: ScriptBuf) -> (OutPoint, TxOut) {
    let tx = cl
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .unwrap();
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == value && spk == txout.script_pubkey {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

fn wait_blocks(bitcoind: &BitcoinD, lightningd: &LightningD) {
    let blockheight = bitcoind.client.get_blockchain_info().unwrap().blocks;
    loop {
        let getinfo = lightningd.client.getinfo().unwrap();
        if getinfo.blockheight == blockheight {
            break
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {
    let _ = env_logger::try_init();

    // Generate keys
    let secp = secp256k1::Secp256k1::new();
    let alice_sk   = secp256k1::SecretKey::from_slice(&b"alice's key plus pad for valid k"[..]).unwrap();
    let bob_sk     = secp256k1::SecretKey::from_slice(&b"bob's key plus pad for valid key"[..]).unwrap();
    let alice_priv = bitcoin::PrivateKey::new(alice_sk, Network::Regtest);
    let bob_priv    = bitcoin::PrivateKey::new(bob_sk, Network::Regtest);
    let alice_pk = bitcoin::PublicKey::from_private_key(&secp, &alice_priv);
    let bob_pk = bitcoin::PublicKey::from_private_key(&secp, &bob_priv);
    println!("pk: alice {:?}", alice_pk);
    println!("pk: bob   {:?}", bob_pk);
    
    // Generate address
    let alice_address = Address::p2shwpkh(&alice_pk, Network::Regtest).unwrap();
    let bob_address = Address::p2shwpkh(&bob_pk, Network::Regtest).unwrap();
    println!("addr: alice {:?}", alice_address);
    println!("addr: bob   {:?}", bob_address);

    // Start bitcoind
    let _ = env_logger::try_init();
    let bitcoind_exe = exe_path().unwrap();
    let bitcoind = bitcoind::BitcoinD::new(bitcoind_exe).unwrap();
    let alice = create_wallet(&bitcoind, "alice", true);
    let bob = create_wallet(&bitcoind, "bob", true);
    let dummy = create_wallet(&bitcoind, "dummy", false);
    let dummy_address = dummy.get_new_address(None, None).unwrap().assume_checked();
    bitcoind.client.generate_to_address(200, &dummy_address).unwrap();

    // Import wallets
    let checksum = bitcoind.client.get_descriptor_info(&format!("addr({})", alice_address)).unwrap().checksum;
    let alice_descriptor = format!("addr({})#{:?}", alice_address, checksum);
    alice.import_descriptors(json::ImportDescriptors { 
        descriptor: alice_descriptor, 
        ..Default::default()
    }).unwrap();
    let checksum = bitcoind.client.get_descriptor_info(&format!("addr({})", bob_address)).unwrap().checksum;
    let bob_descriptor = format!("addr({})#{:?}", bob_address, checksum);
    bob.import_descriptors(json::ImportDescriptors { 
        descriptor: bob_descriptor, 
        ..Default::default()
    }).unwrap();

    // Setup lightning nodes
    let exe = std::env::var("LIGHTNINGD_EXE")
    .expect("LIGHTNINGD_EXE env var pointing to `lightningd` executable is required");
    let mut conf = lightningd::conf::Conf::default();
    conf.view_stdout = true;
    conf.p2p = lightningd::conf::P2P {
        connect: None,
        listen_announce:lightningd::conf::ListenAnnounce::Listen,
    };
    let ln_bob = LightningD::with_conf(&exe, &bitcoind, &conf).unwrap();
    println!("id_host: ln_bob {:?}", ln_bob.id_host());

    conf.p2p = lightningd::conf::P2P {
        connect: ln_bob.id_host().cloned(),
        listen_announce: lightningd::conf::ListenAnnounce::Listen,
    };

    let ln_charlie = LightningD::with_conf(&exe, &bitcoind, &conf).unwrap();
    println!("id_host: ln_charlie {:?}", ln_bob.id_host());
    let list_peers = ln_charlie.client.listpeers(None, None).unwrap();
    assert_eq!(list_peers.peers.len(), 1);
    println!("getinfo: ln_bob {:?}", ln_bob.client.getinfo().unwrap());
    println!("getinfo: ln_charlie {:?}", ln_charlie.client.getinfo().unwrap());

    // Generate blocks and send funds to alice
    let ln_bob_newaddress = ln_bob.client.newaddr(None).unwrap();
    println!("ln_bob_newaddress {:?}", ln_bob_newaddress);
    let ln_bob_address = Address::from_str(&ln_bob_newaddress.bech32.unwrap()).unwrap().assume_checked();
    dummy.send_to_address(&ln_bob_address, btc(1), 
        None,
        None,
        None,
        None,
        None,
        None,
    ).unwrap();
    bitcoind.client.generate_to_address(6, &dummy_address).unwrap();
    wait_blocks(&bitcoind, &ln_bob);
    wait_blocks(&bitcoind, &ln_charlie);
    println!("getinfo: ln_bob {:?}", ln_bob.client.getinfo().unwrap());
    println!("balance: alice {}", alice.get_balances().unwrap().mine.trusted);
    println!("balance: bob   {}", bob.get_balances().unwrap().mine.trusted);
    println!("balance: ln_bob   {:?}", ln_bob.client.listfunds().unwrap());
    let ln_fund_channel = ln_bob.client.fundchannel(&ln_charlie.id_host().unwrap().id.as_str(), requests::AmountOrAll::Amount(1_000_000), None).unwrap();
    println!("ln_fund_channel {:?}", ln_fund_channel);
    bitcoind.client.generate_to_address(6, &dummy_address).unwrap();
    wait_blocks(&bitcoind, &ln_bob);
    wait_blocks(&bitcoind, &ln_charlie);

    // charlie generates invoice
    let ln_charlie_invoice = ln_charlie.client.invoice(Some(10_000_000), "first", "first", None, None, None).unwrap();
    println!("ln_charlie invoice {:?}", ln_charlie_invoice);
    let payment_hash = ln_charlie_invoice.payment_hash;

    // Generate HTLC
    let policy = format!("or(10@and(pk({}),sha256({})),1@and(pk({}),older(10)))", alice_pk, payment_hash, bob_pk);
    println!("htlc policy {:?}", policy);
    let htlc_policy = Concrete::<bitcoin::PublicKey>::from_str(&policy)
        .unwrap()
        .compile()
        .expect("Policy compilation only fails on resource limits or mixed timelocks");
    let htlc_descriptor = Descriptor::new_wsh(htlc_policy)
        .expect("Resource limits");
    let htlc_address = htlc_descriptor
        .address(Network::Regtest)
        .unwrap();
    println!("htlc address: {}", htlc_address.to_string());


    // alice sends btc to htlc
    bitcoind.client.generate_to_address(1, &alice_address).unwrap();
    let txid = dummy.send_to_address(&htlc_address, Amount::from_sat(10_000), 
        None,
        None,
        None,
        None,
        None,
        None,
    ).unwrap();
    println!("send alice -> htlc txid {}", txid);
    let tx = dummy.get_raw_transaction_hex(&txid, None).unwrap();
    println!("send alice -> htlc tx {}", tx);
    dummy.generate_to_address(6, &dummy_address).unwrap();
    
    // bob pays invoice to charlie
    let ln_bob_pay = ln_bob.client.pay(&ln_charlie_invoice.bolt11, PayOptions::default()).unwrap();
    println!("ln pay bob -> charlie {:?}", ln_bob_pay);

    // bob create psbt
    let (outpoint, witness_utxo) = get_vout(&dummy, txid, Amount::from_sat(10_000), htlc_descriptor.script_pubkey());
    let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: miniscript::bitcoin::Sequence::MAX, // Disable LockTime and RBF.
                witness: miniscript::bitcoin::Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: dummy_address.script_pubkey(),
                }
            ],
    };

    let mut psbt = miniscript::bitcoin::psbt::Psbt::from_unsigned_tx(tx.clone()).unwrap();
    let mut input = miniscript::bitcoin::psbt::Input { witness_utxo: Some(witness_utxo), ..Default::default() };
    input.witness_script = Some(htlc_descriptor.explicit_script().unwrap());
    let ty = bitcoin::psbt::PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
    input.sighash_type = Some(ty);
    psbt.inputs = vec![input];

    // bob resolve htlc spending policy
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, None)
        .unwrap()
        .to_secp_msg();
    let data = hex::decode(ln_bob_pay.payment_preimage).unwrap().to_vec();
    psbt.inputs[0].sha256_preimages.insert(sha256::Hash::hash(&data), data);
    let sig1 = secp.sign_ecdsa(&msg, &alice_sk);
    assert!(secp.verify_ecdsa(&msg, &sig1, &alice_pk.inner).is_ok());
    psbt.inputs[0].partial_sigs.insert(alice_pk, bitcoin::ecdsa::Signature { sig: sig1, hash_ty: bitcoin::sighash::EcdsaSighashType::All }, );

    // finalize psbt
    if let Err(e) = psbt.finalize_mut(&secp) {
        // All miniscripts should satisfy
        panic!(
            "Could not satisfy non-malleably: error{} desc:{} ",
            e[0], htlc_descriptor
        );
    }
    let tx = psbt.extract(&secp).expect("Extraction error");
    println!("send bob -> alice tx {:?}", tx);

    // send psbt
    let txid = dummy
        .send_raw_transaction(&tx)
        .unwrap();
    println!("{}",txid);
    println!("send bob -> alice txid {:?}", txid);

}
