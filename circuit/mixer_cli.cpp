// Copyright (c) 2018 HarryR
// License: GPL-3.0+

#include <cstring>
#include <iostream> // cerr
#include <fstream>  // ofstream

#include "mixer.cpp"
#include "stubs.hpp"
#include "export.hpp"
#include "utils.hpp" // hex_to_bytes

using std::cerr;
using std::cout;
using std::endl;
using std::ofstream;

using ethsnarks::mod_mixer;
using ethsnarks::stub_main_genkeys;
using ethsnarks::stub_main_verify;
using ethsnarks::dump_pb_r1cs_constraints;

static int main_prove(int argc, char **argv)
{
    if (argc < (9 + (int)MIXER_TREE_DEPTH))
    {
        cerr << "Usage: " << argv[0] << " prove <pk.raw> <proof.json> <public:root> <public:wallet> <public:nullifier> <secret:nullifier-secret> <secret:merkle-address> <secret:merkle-path ...>" << endl;
        cerr << "Args: " << endl;
        cerr << "\t<pk.raw>           Path to proving key" << endl;
        cerr << "\t<proof.json>       Write proof to this file" << endl;
        cerr << "\t<root>             Merkle tree root" << endl;
        cerr << "\t<wallet>           Withdrawing Wallet Address" << endl;
        cerr << "\t<nullifier>        Nullifier" << endl;
        cerr << "\t<nullifier-secret> Nullifier Preimage" << endl;
        cerr << "\t<merkle-address>   0 and 1 bits for tree path" << endl;
        cerr << "\t<merkle-path...>   items for merkle tree path" << endl;
        return 1;
    }

    auto pk_filename = argv[2];
    auto proof_filename = argv[3];
    auto arg_root = argv[4];
    auto arg_wallet_address = argv[5];
    auto arg_nullifier = argv[6];
    auto arg_nullifier_secret = argv[7];
    auto arg_address = argv[8];

    const char *arg_path[MIXER_TREE_DEPTH];
    for (size_t i = 0; i < MIXER_TREE_DEPTH; i++)
    {
        arg_path[i] = argv[9 + i];
    }

    auto json = mixer_prove(pk_filename, arg_root, arg_wallet_address, arg_nullifier, arg_nullifier_secret, arg_address, arg_path);

    ofstream fh;
    fh.open(proof_filename, std::ios::binary);
    fh << json;
    fh.flush();
    fh.close();

    return 0;
}


const std::string read_all_stdin () {
    // don't skip the whitespace while reading
    std::cin >> std::noskipws;
    // use stream iterators to copy the stream to a string
    std::istream_iterator<char> it(std::cin);
    std::istream_iterator<char> end;
    return std::string(it, end);
}


static int main_prove_json( int argc, char **argv )
{
    if( argc < 3 ) {
        std::cerr << "Usage: " << argv[0] << " prove_json <proving.key> [output_proof.json]\n";
        return 1;
    }

    auto json_buf = read_all_stdin();
    auto pk_filename = argv[2];

    auto proof_json = mixer_prove_json(pk_filename, json_buf.c_str());
    if( proof_json == nullptr ) {
        std::cerr << "Failed to prove\n";
        return 2;
    }

    // output to stdout by default
    if( argc < 4 ) {
        std::cout << proof_json;
        return 0;
    }

    // Otherwise outtput to specific file
    ofstream fh;
    fh.open(argv[3], std::ios::binary);
    fh << proof_json;
    fh.flush();
    fh.close();

    std::cerr << "OK\n";

    return 0;
}


static int main_debug_pk( int argc, char **argv )
{
    ppT::init_public_params();

    if( argc < 3 ) {
        std::cerr << "Error: must specify proving key file" << std::endl;
        return 1;
    }

    const auto proving_key = ethsnarks::loadFromFile<ethsnarks::ProvingKeyT>(argv[2]);

    std::cout << "Alpha G1" << std::endl;
    std::cout << ethsnarks::outputPointG1AffineAsHex(proving_key.alpha_g1) << std::endl;

    std::cout << "Beta G1" << std::endl;
    std::cout << ethsnarks::outputPointG1AffineAsHex(proving_key.beta_g1) << std::endl;

    std::cout << "Beta G2" << std::endl;
    std::cout << ethsnarks::outputPointG2AffineAsHex(proving_key.beta_g2) << std::endl;

    std::cout << "Delta G1" << std::endl;
    std::cout << ethsnarks::outputPointG1AffineAsHex(proving_key.delta_g1) << std::endl;

    std::cout << "Delta G2" << std::endl;
    std::cout << ethsnarks::outputPointG2AffineAsHex(proving_key.delta_g2) << std::endl;
    
    std::cout << "A Query" << std::endl;
    for( const auto &Aq1 : proving_key.A_query ) {
        std::cout << ethsnarks::outputPointG1AffineAsHex(Aq1) << std::endl;
    }

    std::cout << "B Query" << std::endl;
    for( size_t i = 0; i < proving_key.B_query.domain_size(); i++ ) {
        const auto &Bq = proving_key.B_query[i];
        std::cout << ethsnarks::outputPointG1AffineAsHex(Bq.h) << std::endl;
        std::cout << ethsnarks::outputPointG2AffineAsHex(Bq.g) << std::endl;
    }

    std::cout << "H Query" << std::endl;
    for( const auto &Hq1 : proving_key.H_query ) {
        std::cout << ethsnarks::outputPointG1AffineAsHex(Hq1) << std::endl;
    }

    std::cout << "L Query" << std::endl;
    for( const auto &Lq1 : proving_key.L_query ) {
        std::cout << ethsnarks::outputPointG1AffineAsHex(Lq1) << std::endl;
    }

    return 0;
}


int main(int argc, char **argv)
{
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <genkeys|prove|prove_json|verify|constraints|debug_pk> [...]" << endl;
        return 1;
    }

    if (0 == ::strcmp(argv[1], "prove"))
    {
        return main_prove(argc, argv);
    }
    if (0 == ::strcmp(argv[1], "prove_json"))
    {
        return main_prove_json(argc, argv);
    }
    else if (0 == ::strcmp(argv[1], "genkeys"))
    {
        return stub_main_genkeys<mod_mixer>(argv[0], argc - 1, &argv[1]);
    }
    else if (0 == ::strcmp(argv[1], "verify"))
    {
        return stub_main_verify(argv[0], argc - 1, (const char **)&argv[1]);
    }
    else if (0 == ::strcmp(argv[1], "debug_pk") ) {
        return main_debug_pk(argc, argv);
    }
    else if (0 == ::strcmp(argv[1], "constraints")) {
        ppT::init_public_params();
        ProtoboardT pb;
        ethsnarks::mod_mixer mod(pb, "module");
        mod.generate_r1cs_constraints();
        dump_pb_r1cs_constraints(pb);
        return 0;
    }

    cerr << "Error: unknown sub-command " << argv[1] << endl;
    return 2;
}
