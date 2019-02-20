//
//  MixerManager.swift
//  iOSProver
//
//  Created by Olivier van den Biggelaar on 14/02/2019.
//  Copyright © 2019 Olivier van den Biggelaar. All rights reserved.
//

import Foundation
import Web3
import struct web3swift.Swift.EventParserResult

class MixerManager {
    
    enum MixerError: Error {
        case contractCallFailed(String)
        case invalidParams(String)
        case internalError(String)
        case unexpectedDataReceived(String)
    }
    
    static let shared: MixerManager = MixerManager()
    
    let mixerAddressStr  = "0x78c85Fdc92A93EE75566688f97e9e532d573C853"
    private let rpcPath = "https://rinkeby.infura.io/v3/91ffab09868d430f9ce744c78d7ff427" // "http://127.0.0.1:8545"
    private let relayerEndpoint = "http://localhost:8080"
    private lazy var web3 = Web3(rpcURL: rpcPath)
    private lazy var mixer = MixerFactory.mixer(web3: web3, mixerAddressStr: mixerAddressStr)
    private lazy var mixerRelayer = mixer != nil ? MixerRelayer(web3: web3, endPoint: relayerEndpoint, mixer: mixer!) : nil
    private let prover = Prover.shared
    
    private init() {}

    // MARK: - Helper functions to compute call parameters
    
    func getLeaf(nullifierSecret: BigUInt, fundedAddress: EthereumAddress) -> Promise<BigUInt> {
        return Promise { seal in
            self.mixer?["makeLeafHash"]?(nullifierSecret, fundedAddress).call { (result, error) in
                seal.resolve(result?[""] as? BigUInt, error)
            }
        }
    }
    
    func getNullifier(nullifierSecret: BigUInt) -> Promise<BigUInt>  {
        return Promise { seal in
            self.mixer?["makeNullifierHash"]?(nullifierSecret).call { (result, error) in
                seal.resolve(result?[""] as? BigUInt, error)
            }
        }
    }
    
    func getMerklePath(leafIndex: BigUInt) -> Promise<[BigUInt]>  {
        return Promise { seal in
            self.mixer?["getMerklePath"]?(leafIndex).call { (result, error) in
                seal.resolve(result?["out_path"] as? [BigUInt], error)
            }
        }
    }
    
    func getRoot() -> Promise<BigUInt>  {
        return Promise { seal in
            self.mixer?["getRoot"]?().call { (result, error) in
                seal.resolve(result?[""] as? BigUInt, error)
            }
        }
    }
    
    
    // MARK: - Contract convenience methods
    
    func commit(fundedAddress: EthereumAddress,
                funderAddress: EthereumAddress,
                secret: BigUInt,
                txWasSubmitted: TransactionSubmittedCallback? = nil,
                txWasMined: TransactionMinedCallback? = nil) {
        firstly {
            getLeaf(nullifierSecret: secret, fundedAddress: fundedAddress)
        }.done { [weak self] leaf in
            self?.mixerRelayer?.commit(leaf: leaf,
                                       funderAddress: funderAddress,
                                       txWasSubmitted: txWasSubmitted,
                                       txWasMined: txWasMined)
        }.catch { error in
            txWasSubmitted?(nil, MixerError.contractCallFailed("getLeaf() failed: \(error.localizedDescription)"))
        }
    }
    
    func watchFundingEvent(fundedAddress: EthereumAddress,
                           secret: BigUInt,
                           startBlock: UInt64 = 3_861_629,
                           commitmentWasFunded: @escaping (_ result: (blockNumber: UInt64, leafIndex: BigUInt)?, _ error: Error?) -> ()) {
        guard let abiData = MixerFactory.abiData else {
            commitmentWasFunded(nil, MixerError.invalidParams("Invalid ABI"))
            return
        }

        firstly {
            getLeaf(nullifierSecret: secret, fundedAddress: fundedAddress)
        }.then { [weak self] leaf -> Promise<[EventParserResult]> in
            guard let this = self else { throw MixerError.internalError("self is nil") }
            return EventFetcher.fetchEventsPromise(
                rpcPath: this.rpcPath,
                name: "LeafAdded",
                abiData: abiData,
                contractAddress: this.mixerAddressStr,
                startBlock: startBlock,
                pollingPeriod: 5,
                filters: ["_leaf": leaf])
        }.done { result in
            guard
                let last = result.last,
                let leafIdx = last.decodedResult["_leafIndex"] as? BigUInt,
                let blockStr = last.eventLog?.blockNumber.description,
                let block = UInt64(hexString: String(blockStr.dropFirst(2)))
            else {
                throw MixerError.unexpectedDataReceived("Could not parse funding event result")
            }
            commitmentWasFunded((block, leafIdx), nil)
        }.catch { error in
            commitmentWasFunded(nil, error)
        }
    }
    
    func withdraw(fundedAddress: EthereumAddress,
                  funderAddress: EthereumAddress,
                  secret: BigUInt,
                  leafIndex: BigUInt,
                  proofWasComputed: (() -> ())? = nil,
                  txWasSubmitted: TransactionSubmittedCallback? = nil,
                  txWasMined: TransactionMinedCallback? = nil) {
        var nullifier: BigUInt!
        var merklePath = [BigUInt]()
        
        firstly {
            getMerklePath(leafIndex: leafIndex)
        }.then { [weak self] mpath -> Promise<BigUInt> in
            guard let this = self else { throw MixerError.internalError("self is nil") }
            merklePath = mpath
            return this.getNullifier(nullifierSecret: secret)
        }.then { [weak self] null -> Promise<BigUInt> in
            guard let this = self else { throw MixerError.internalError("self is nil") }
            nullifier = null
            return this.getRoot()
        }.then { [weak self] root -> Promise<[BigUInt]> in
            guard let this = self else { throw MixerError.internalError("self is nil") }
            return this.prover.buildFlatProofPromise(root: root,
                                                     fundedAddress: fundedAddress,
                                                     nullifier: nullifier,
                                                     nullifierSecret: secret,
                                                     leafIndex: leafIndex,
                                                     merklePath: merklePath)
        }.done { [weak self] flatProof in
            proofWasComputed?()
            self?.mixerRelayer?.withdraw(fundedAddress: fundedAddress,
                                         nullifier: nullifier,
                                         flatProof: flatProof,
                                         txWasSubmitted: txWasSubmitted,
                                         txWasMined: txWasMined)
        }.catch { error in
            txWasSubmitted?(nil, error)
        }
    }
}
