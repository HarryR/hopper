const Mixer = artifacts.require("Mixer");

const crypto = require("crypto");
const fs = require("fs");

const chai = require("chai");
const bnChai = require("bn-chai");
const { expect } = chai;
const { BN, toBN } = web3.utils;
chai.use(bnChai(BN));

const AMOUNT = web3.utils.toWei("1", "ether");

const path = require("path");
const VERIFYING_KEY_PATH = path.resolve("../.keys/mixer.vk.json");
const PROVING_KEY_PATH = path.resolve("../.keys/mixer.pk.raw");
const vk = require(VERIFYING_KEY_PATH);
const { proof_to_flat, vk_to_flat } = require("../utils");

const { mixer_prove, mixer_prove_json, mixer_verify } = require("./helpers/libmixer");


/**
* If the WASM prover is available, return its `prove_json` method
* This allows WASM proving to be dropped-in wherever native proving is
* To ensure compatibilty between WASM vs Native builds and on-chain contracts
*/
function _get_wasm_prover()
{
    const wasm_js_file = path.resolve('../wasm/example/mixer_js.js');
    if( fs.existsSync(wasm_js_file) )
    {
        const mixer_wasm = require(wasm_js_file);
        console.log('Loaded WASM prover...');

        // Load the proving key into the WASM context
        const proving_key_data = fs.readFileSync(PROVING_KEY_PATH);
        mixer_wasm.FS_createDataFile('/', 'mixer.pk.raw', proving_key_data, true, false, false);

        const prove_json = mixer_wasm.cwrap('mixer_prove_json', 'string', ['string', 'string']);
        const verify = mixer_wasm.cwrap('mixer_verify', 'bool', ['string', 'string']);

        return { prove_json, verify };
    }
}
const wasm_mixer = _get_wasm_prover();

const SKIP_SLOW_TESTS = true;


contract("Mixer", function([
  depositer1,
  depositer2,
  depositer3,
  withdrawer1,
  withdrawer2,
  withdrawer3,
  relayer
]) {
  beforeEach(async () => {
    this.mixer = await Mixer.new(...vk_to_flat(vk));
  });

  async function deposit(_depositer = depositer1, _withdrawer = withdrawer1) {
    const nullifier_secret = toBN(crypto.randomBytes(30).toString("hex"));
    const leaf = await this.mixer.makeLeafHash(nullifier_secret, _withdrawer);

    // Send commitment
    await this.mixer.commit(leaf, _depositer, { from: relayer });

    // Fund commitment
    const receipt = await this.mixer.send(AMOUNT, { from: _depositer });
    const leaf_index = receipt.logs.filter(l => l.event == "LeafAdded")[0].args
      ._leafIndex;
    console.log(`Funding commitment cost ${receipt.receipt.gasUsed} gas`);

    return { nullifier_secret, leaf_index };
  }

  async function computeProof(
    _nullifier_secret,
    _leaf_index,
    _withdrawer = withdrawer1,
    _prover = undefined,
    _proving_key = undefined
  ) {
    _prover = _prover || mixer_prove_json;  // Prover can be swapped...
    _proving_key = _proving_key || PROVING_KEY_PATH;

    // Compute leaf binary address
    const tree_depth = (await this.mixer.treeDepth()).toNumber();
    // Compute merkle path neighbour hashes
    const path_neighbours = await this.mixer.getMerklePath(_leaf_index);
    // Compute merkle root
    const merkle_root = await this.mixer.getRoot();
    // Compute nullifier
    const nullifier = await this.mixer.makeNullifierHash(_nullifier_secret);

    // Generate proof
    let args_json = JSON.stringify({
      "root": merkle_root.toString(10),
      "wallet_address": toBN(_withdrawer).toString(10),
      "nullifier": nullifier.toString(10),
      "nullifier_secret": _nullifier_secret.toString(10),
      "address": _leaf_index.toNumber(),
      "path": path_neighbours.map(h => h.toString(10))
    });
    console.log('Input proof args (json):', args_json);
    const proof_json = _prover(_proving_key, args_json);

    assert.notEqual(
      proof_json,
      null,
      "Failed to build valid proof (invalid proof inputs)"
    );
    console.log('Output proof result (json)', proof_json);

    return { proof_json, nullifier, merkle_root };
  }

  async function verifyProof(
    _proof_json,
    _nullifier,
    _merkle_root,
    _withdrawer = withdrawer1,
    _verifier = undefined
  ) {
    _verifier = _verifier || mixer_verify;
    const proof = JSON.parse(_proof_json);

    // Ensure proof inputs match our public variables
    assert.deepStrictEqual(
      [...proof.input].sort(),
      [
        "0x" + _merkle_root.toString(16),
        "0x" + toBN(_withdrawer).toString(16),
        "0x" + _nullifier.toString(16)
      ].sort()
    );

    // Verify proof using native library
    // XXX: node-ffi on OSX will not null-terminate strings returned from `readFileSync` !
    const proof_valid_native = _verifier(
      fs.readFileSync(VERIFYING_KEY_PATH) + "\0",
      _proof_json
    );
    assert.isTrue(proof_valid_native === true || proof_valid_native === 1);

    // Verify proof using Verifier contract
    const proof_valid_contract = await this.mixer.verifyProof(
      _merkle_root,
      _withdrawer,
      _nullifier,
      proof_to_flat(proof)
    );
    assert.isTrue(proof_valid_contract);
  }

  describe("Deposit & Withdraw", () => {
    it("deposits then withdraws", async () => {
      const mixerBeforeD = toBN(await web3.eth.getBalance(this.mixer.address));
      // Send the commitment and fund it
      const { nullifier_secret, leaf_index } = await deposit();
      const mixerAfterD = toBN(await web3.eth.getBalance(this.mixer.address));
      expect(mixerAfterD.sub(mixerBeforeD)).to.eq.BN(AMOUNT);

      // Compute and verify the proof
      let { proof_json, nullifier, merkle_root } = await computeProof(
        nullifier_secret,
        leaf_index
      );
      await verifyProof(proof_json, nullifier, merkle_root);

      if( wasm_mixer ) {
        console.log('Testing native proof with WASM verifier');
        await verifyProof(proof_json, nullifier, merkle_root, withdrawer1, wasm_mixer.verify);

        console.log('Testing WASM prover');
        let proof_wasm = await computeProof(
          nullifier_secret,
          leaf_index,
          withdrawer1,
          wasm_mixer.prove_json,
          '/mixer.pk.raw'
        );

        console.log('Verify WASM proof with WASM verifier');
        await verifyProof(proof_wasm.proof_json, proof_wasm.nullifier, proof_wasm.merkle_root, withdrawer1, wasm_mixer.verify);

        console.log('Verify WASM proof with Native verifier');
        await verifyProof(proof_wasm.proof_json, proof_wasm.nullifier, proof_wasm.merkle_root);
      }

      // Verify nullifier doesn't exist
      let is_nullifier_spent = await this.mixer.isSpent(nullifier);
      assert.isFalse(is_nullifier_spent);

      // Perform the withdrawal
      const withdrawerBeforeW = toBN(await web3.eth.getBalance(withdrawer1));
      const mixerBeforeW = toBN(await web3.eth.getBalance(this.mixer.address));
      const proof = JSON.parse(proof_json);
      const receipt = await this.mixer.withdraw(
        withdrawer1,
        nullifier,
        proof_to_flat(proof),
        { from: relayer }
      );
      console.log(`Withdrawing used ${receipt.receipt.gasUsed} gas`);

      const withdrawerAfterW = toBN(await web3.eth.getBalance(withdrawer1));
      const mixerAfterW = toBN(await web3.eth.getBalance(this.mixer.address));
      expect(withdrawerAfterW).to.be.gt.BN(withdrawerBeforeW);
      expect(mixerBeforeW.sub(mixerAfterW)).to.eq.BN(AMOUNT);

      // Verify nullifier exists
      is_nullifier_spent = await this.mixer.isSpent(nullifier);
      assert.isTrue(is_nullifier_spent);
    });

    it("deposits 3 times then withdraws 3 times", async () => {
      if (SKIP_SLOW_TESTS) return;

      depositers = [depositer1, depositer1, depositer3];
      withdrawers = [withdrawer1, withdrawer2, withdrawer3];
      commitments = [];

      for (let i = 0; i < depositers.length; i++) {
        const mixerBeforeD = toBN(
          await web3.eth.getBalance(this.mixer.address)
        );
        // Send the commitment and fund it
        commitments.push(await deposit(depositers[i], withdrawers[i]));
        const mixerAfterD = toBN(await web3.eth.getBalance(this.mixer.address));
        expect(mixerAfterD.sub(mixerBeforeD)).to.eq.BN(AMOUNT);
      }

      for (let i = 0; i < depositers.length; i++) {
        const { nullifier_secret, leaf_index } = commitments[i];
        // Compute and verify the proof
        const { proof_json, nullifier, merkle_root } = await computeProof(
          nullifier_secret,
          leaf_index,
          withdrawers[i]
        );
        await verifyProof(proof_json, nullifier, merkle_root, withdrawers[i]);

        // Verify nullifier doesn't exist
        let is_nullifier_spent = await this.mixer.isSpent(nullifier);
        assert.isFalse(is_nullifier_spent);

        // Perform the withdrawal
        const withdrawerBeforeW = toBN(
          await web3.eth.getBalance(withdrawers[i])
        );
        const mixerBeforeW = toBN(
          await web3.eth.getBalance(this.mixer.address)
        );
        const proof = JSON.parse(proof_json);
        await this.mixer.withdraw(
          withdrawers[i],
          nullifier,
          proof_to_flat(proof)
        );
        const withdrawerAfterW = toBN(
          await web3.eth.getBalance(withdrawers[i])
        );
        const mixerAfterW = toBN(await web3.eth.getBalance(this.mixer.address));
        expect(withdrawerAfterW).to.be.gt.BN(withdrawerBeforeW);
        expect(mixerBeforeW.sub(mixerAfterW)).to.eq.BN(AMOUNT);

        // Verify nullifier exists
        is_nullifier_spent = await this.mixer.isSpent(nullifier);
        assert.isTrue(is_nullifier_spent);
      }
    });
  });
});
