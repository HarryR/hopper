// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

// Copyright (c) 2018 HarryR
// License: GPL-3.0+

/**
* This module contains stuff for unserialising the verify key and proofs
* from JSON stuff. It's the opposite of 'export.cpp'...
*/

#include <cassert>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <gmp.h>

#include "import.hpp"

using libsnark::r1cs_gg_ppzksnark_zok_proof;
using libsnark::r1cs_gg_ppzksnark_zok_verification_key;
using libsnark::accumulation_vector;
using libsnark::r1cs_gg_ppzksnark_zok_primary_input;

using std::string;
using std::vector;
using std::stringstream;


#include <nlohmann/json.hpp>
using json = nlohmann::json;


namespace ethsnarks {


FqT parse_Fq(const string &input) {
    return parse_bigint<FqT>(input);
}


FieldT parse_FieldT(const string &input) {
    return parse_bigint<FieldT>(input);
}


/**
* Create a list of F<x> elements from a node in a property tree, in JSON this is:
*
*   [N, N, N, ...]
*/
vector<FieldT> create_F_list( const json &in_tree )
{
    vector<FieldT> elements;

    for( auto& item : in_tree )
    {
        elements.emplace_back( parse_FieldT( item ) );
    }

    return elements;
}


/**
* Create a G1 point from X and Y coords (integers or hex as strings)
*
* This assumes the coordinates are affine.
*/
G1T create_G1(const string &in_X, const string &in_Y)
{
    return G1T(parse_Fq(in_X), parse_Fq(in_Y), FqT("1"));

    // TODO: verify well_formed
}


/**
* Create a G2 point from 512bit big-endian X and Y coords (integers or hex as strings)
*
*   X.c1, X.c0, Y.c1, Y.c0
*
* This assumes the coordinates are affine.
*/
G2T create_G2(const string &in_X_c1, const string &in_X_c0, const string &in_Y_c1, const string &in_Y_c0)
{
    typedef typename ppT::Fqe_type Fq2_T;

    return G2T(
        Fq2_T(parse_Fq(in_X_c0), parse_Fq(in_X_c1)),
        Fq2_T(parse_Fq(in_Y_c0), parse_Fq(in_Y_c1)),
        Fq2_T(FqT("1"), FqT("0")));   // Z is hard-coded, coordinates are affine

    // TODO: verify well_formed
}


/**
* Create a G1 element from a node in a property tree, in JSON this is:
*
*   "in_key": ["X", "Y"]
*/
G1T create_G1( const json &in_tree )
{
    assert(in_tree.size() == 2);
    return create_G1(in_tree[0].get<string>(), in_tree[1].get<string>());
}


/**
* Create a list of G1 points from a node in a property tree, in JSON this is:
*
*   "in_key": [["X", "Y"], ["X", "Y"], ...]
*/
vector<G1T> create_G1_list( const json &in_tree )
{
    typedef typename ppT::G1_type G1_T;

    vector<G1_T> points;

    for( auto& item : in_tree )
    {
        points.emplace_back( create_G1(item) );
    }

    return points;
}



/**
* Create a G2 element from a node in a property tree, in JSON this is:
*
*   [["X.c1", "X.c0"], ["Y.c1", "Y.c0"]]
*/
G2T create_G2( const json &in_tree )
{
    assert( in_tree.size() == 2 );
    assert( in_tree[0].size() == 2 );
    assert( in_tree[1].size() == 2 );

    return create_G2(in_tree[0][0].get<string>(), in_tree[0][1].get<string>(),
                     in_tree[1][0].get<string>(), in_tree[1][1].get<string>());
}



/**
* Parse the witness/proof from a property tree
*   {"A": g1,
*    "B": g2,
*    "C": g1,
*    "input": [N, N, N ...]}
*/
InputProofPairType proof_from_json( const json &in_tree )
{
    auto A = create_G1(in_tree.at("A"));
    auto B = create_G2(in_tree.at("B"));
    auto C = create_G1(in_tree.at("C"));
    auto input = create_F_list(in_tree.at("input"));

    ProofT proof(
        std::move(A),
        std::move(B),
        std::move(C));

    return InputProofPairType(input, proof);
}


/**
* Parse the witness/proof from a stream of JSON encoded data
*/
InputProofPairType proof_from_json( stringstream &in_json )
{
    return proof_from_json(json::parse(in_json));
}


/**
* Parse the verification key from a property tree
*
*   {"alpha": g1,
*    "beta": g2,
*    "gamma": g2,
*    "delta": g2,
*    "gamma_ABC": [g1, g1, g1...]}
*/
VerificationKeyT vk_from_json( const json &in_tree )
{
    // Array of IC G1 points
    auto gamma_ABC_g1 = create_G1_list(in_tree.at("gammaABC"));
    auto alpha_g1 = create_G1(in_tree.at("alpha"));
    auto beta_g2 = create_G2(in_tree.at("beta"));
    auto gamma_g2 = create_G2(in_tree.at("gamma"));
    auto delta_g2 = create_G2(in_tree.at("delta"));

    // IC must be split into `first` and `rest` for the accumulator
    auto gamma_ABC_g1_rest = decltype(gamma_ABC_g1)(gamma_ABC_g1.begin() + 1, gamma_ABC_g1.end());
    auto gamma_ABC_g1_vec = accumulation_vector<G1T>(std::move(gamma_ABC_g1[0]), std::move(gamma_ABC_g1_rest));

    return VerificationKeyT(
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_ABC_g1_vec);
}


/**
* Parse the verifying key from a stream of JSON encoded data
*/
VerificationKeyT vk_from_json( stringstream &in_json )
{
    return vk_from_json(json::parse(in_json));
}

// ethsnarks
}