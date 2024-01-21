// Reverse submarine swap

// Alice = user: pay lightning invoice
// Bob = lock onchain btc into htlc

// 1. Alice generates an preimage and send to Bob
// 2. Bob generate an invoice and send to Alice
// 3. Alice pays the invoice
// 4. Bob send funds to htlc with the Alice preimage
// 5. Alice spend the psbt

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
use rand::RngCore;
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

fn bitcoin_create_wallet(bitcoind: &BitcoinD, label: &str, disable_private_keys: bool) -> Result<Client, bitcoind::bitcoincore_rpc::Error> {
    bitcoind.client.create_wallet(label, Some(disable_private_keys), None, None, None).unwrap();
    Client::new(
        &bitcoind.rpc_url_with_wallet(label),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
}

fn bitcoin_import_descriptor(client: &Client, descriptor: String) {
    let checksum = client
        .get_descriptor_info(&descriptor)
        .unwrap()
        .checksum;
    let desc: json::ImportDescriptors = json::ImportDescriptors {
        descriptor: format!("{}#{}", descriptor, checksum.unwrap_or("".to_string())),
        timestamp: json::Timestamp::Now,
        active: None,
        range: None,
        next_index: None,
        internal: None,
        label: None,
    };
    client.import_descriptors(desc).unwrap();
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

fn lightning_wait_blocks(bitcoind: &BitcoinD, lightningd: &LightningD) {
    let blockheight = bitcoind.client.get_blockchain_info().unwrap().blocks;
    loop {
        let getinfo = lightningd.client.getinfo().unwrap();
        if getinfo.blockheight == blockheight {
            break
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn start_lightningd(
    bitcoind: &bitcoind::BitcoinD,
    connect_to_id_host: Option<lightningd::conf::IdHost>,
) -> Result<lightningd::LightningD, lightningd::error::Error> {
    let lightningd_exe = std::env::var("LIGHTNINGD_EXE")
        .expect("LIGHTNINGD_EXE env var pointing to `lightningd` executable is required");
    let mut conf = lightningd::conf::Conf::default();
    //conf.view_stdout = true;
    conf.p2p = lightningd::conf::P2P {
        connect: connect_to_id_host,
        listen_announce: lightningd::conf::ListenAnnounce::Listen,
    };
    lightningd::LightningD::with_conf(&lightningd_exe, bitcoind, &conf)
}

fn main() {
    let _ = env_logger::try_init();

    // Generate keys
    let secp = secp256k1::Secp256k1::new();
    let alice_sk   = secp256k1::SecretKey::from_slice(&b"alice's key plus pad for valid k"[..]).unwrap();
    let bob_sk: secp256k1::SecretKey     = secp256k1::SecretKey::from_slice(&b"bob's key plus pad for valid key"[..]).unwrap();
    let alice_priv = bitcoin::PrivateKey::new(alice_sk, Network::Regtest);
    let bob_priv    = bitcoin::PrivateKey::new(bob_sk, Network::Regtest);
    let alice_pk = bitcoin::PublicKey::from_private_key(&secp, &alice_priv);
    let bob_pk = bitcoin::PublicKey::from_private_key(&secp, &bob_priv);

    // Start bitcoind
    let _ = env_logger::try_init();
    let bitcoind_exe = exe_path().unwrap();
    let bitcoind = bitcoind::BitcoinD::new(bitcoind_exe).unwrap();

    // Import wallets
    let btc_alice = bitcoin_create_wallet(&bitcoind, "alice", false).unwrap();
    let btc_bob = bitcoin_create_wallet(&bitcoind, "bob", false).unwrap();
    let btc_dummy = bitcoin_create_wallet(&bitcoind, "dummy", false).unwrap();
    bitcoin_import_descriptor(&btc_alice, format!("wpkh({})", alice_priv));
    bitcoin_import_descriptor(&btc_bob, format!("wpkh({})", bob_priv));

    // Send initial funds
    let btc_dummy_address = btc_dummy.get_new_address(None, None).unwrap().assume_checked();
    bitcoind.client.generate_to_address(100, &btc_dummy_address).unwrap();
    let btc_bob_address = btc_bob.get_new_address(None, None).unwrap().assume_checked();
    bitcoind.client.generate_to_address(100, &btc_bob_address).unwrap();

    // Setup lightning nodes
    let ln_alice = start_lightningd(&bitcoind, None).unwrap();
    let ln_bob = start_lightningd(&bitcoind, ln_alice.id_host().cloned()).unwrap();
    println!("SETUP NODES");
    println!("ln_alice: getinfo: {:?}", ln_alice.client.getinfo().unwrap());
    println!("ln_alice: listpeers: {:?}", ln_alice.client.listpeers(None, None).unwrap().peers);

    // Fund lightning channel: from alice to bob
    let ln_alice_newaddress = ln_alice.client.newaddr(None).unwrap();
    println!("ln_alice: newaddr: {:?}", ln_alice_newaddress);
    let ln_alice_address = Address::from_str(&ln_alice_newaddress.bech32.unwrap()).unwrap().assume_checked();
    btc_dummy.send_to_address(&ln_alice_address, btc(1), 
        None,
        None,
        None,
        None,
        None,
        None,
    ).unwrap();
    bitcoind.client.generate_to_address(6, &btc_dummy_address).unwrap();
    lightning_wait_blocks(&bitcoind, &ln_alice);
    lightning_wait_blocks(&bitcoind, &ln_bob);
    println!("ln_alice: listfunds:   {:?}", ln_alice.client.listfunds().unwrap());
    let ln_fund_channel = ln_alice.client.fundchannel(&ln_bob.id_host().unwrap().id.as_str(), requests::AmountOrAll::Amount(1_000_000), None).unwrap();
    println!("ln_alice: ln_fund_channel: {:?}", ln_fund_channel);
    bitcoind.client.generate_to_address(6, &btc_dummy_address).unwrap();
    lightning_wait_blocks(&bitcoind, &ln_alice);
    lightning_wait_blocks(&bitcoind, &ln_bob);
    println!("ln_alice: listpeers: {:?}", ln_alice.client.listpeers(None, None).unwrap().peers);

    // show balances
    println!("INITIAL BALANCES");
    println!("btc_alice: balance:   {:?}", btc_alice.get_balance(None, None).unwrap().to_sat());
    println!("btc_bob: balance:   {:?}", btc_bob.get_balance(None, None).unwrap().to_sat());    
    println!("ln_alice: out_fulfilled_msat:   {:?}", ln_alice.client.listpeers(None, None).unwrap().peers.first().unwrap().channels.first().unwrap().out_fulfilled_msat);
    println!("ln_bob: in_fulfilled_msat:   {:?}", ln_bob.client.listpeers(None, None).unwrap().peers.first().unwrap().channels.first().unwrap().in_fulfilled_msat);

    // 1. Alice opens her Bob client and wants to send her funds to an on-chain address. 
    // She enters the desired amount and creates a preimage and sends its hash to Bob.
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let preimage_hash = sha256::Hash::hash(&preimage);
    let amount = Amount::from_sat(10_000);

    // 2. Bob creates an invoice using the preimage hash and returns it to Alice.
    let amount_msat = amount.to_sat() * 1_000;
    let preimage_hash_hex = hex::encode(preimage_hash);
    let invoice = ln_bob.client.invoice(
        Some(amount_msat),
        "label", 
        "description", 
        Some(preimage_hash_hex.as_str()), 
        None, 
        None)
        .unwrap();
    
    // 3. Alices pays the invoice to Bob
    let payment = ln_alice.client.pay(&invoice.bolt11, PayOptions::default()).unwrap();
    //let payment_hash = payment.payment_hash.clone();
    println!("ln_alice: pay invoice: {:?}", payment);

    // 4. Bob send an on-chain transaction using a script that requires Alice to reveal her preimage in order to claim the funds.
    let policy = format!("or(10@and(pk({}),sha256({})),1@and(pk({}),older(10)))", alice_pk, preimage_hash_hex, bob_pk);
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

    let txid = btc_bob.send_to_address(&htlc_address, amount, 
        None,
        None,
        None,
        None,
        None,
        None,
    ).unwrap();
    println!("btc_bob: send btc -> htlc txid: {}", txid);
    let tx = btc_bob.get_raw_transaction_hex(&txid, None).unwrap();
    println!("btc_bob: send btc -> htlc tx: {}", tx);
    bitcoind.client.generate_to_address(6, &btc_dummy_address).unwrap();


    // 5. Alice spends from htlc to his own address
    let (outpoint, witness_utxo) = get_vout(&btc_bob, txid, amount, htlc_descriptor.script_pubkey());
    let btc_alice_address = btc_alice.get_new_address(None, None).unwrap().assume_checked();
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
                    script_pubkey: btc_alice_address.script_pubkey(),
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
    psbt.inputs[0].sha256_preimages.insert(sha256::Hash::hash(&preimage), preimage.to_vec());
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
    println!("btc_alice: claim tx from htlc txid: {:?}", tx);

    // send psbt
    let txid = btc_alice
        .send_raw_transaction(&tx)
        .unwrap();
    println!("{}",txid);
    println!("btc_alice: claim tx from htlc txid: {}", txid);
    bitcoind.client.generate_to_address(6, &btc_dummy_address).unwrap();

    // show balances
    println!("FINALE BALANCES");
    println!("btc_alice: balance:   {:?}", btc_alice.get_balance(None, None).unwrap().to_sat());
    println!("btc_bob: balance:   {:?}", btc_bob.get_balance(None, None).unwrap().to_sat());
    println!("ln_alice: out_fulfilled_msat:   {:?}", ln_alice.client.listpeers(None, None).unwrap().peers.first().unwrap().channels.first().unwrap().out_fulfilled_msat);
    println!("ln_bob: in_fulfilled_msat:   {:?}", ln_bob.client.listpeers(None, None).unwrap().peers.first().unwrap().channels.first().unwrap().in_fulfilled_msat);

}