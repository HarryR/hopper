#ifndef ETHSNARKS_EXPORT_HPP_
#define ETHSNARKS_EXPORT_HPP_

#include "ethsnarks.hpp"

namespace ethsnarks {

std::string HexStringFromBigint( const LimbT _x);

std::string outputPointG1AffineAsHex( const G1T _p );

std::string outputPointG2AffineAsHex( const G2T _p );

std::string proof_to_json( const ProofT &proof, const PrimaryInputT &input );

std::string vk2json( const VerificationKeyT &vk );

void vk2json_file( const VerificationKeyT &vk, const std::string &path );

}

#endif
