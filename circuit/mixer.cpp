/*    
    Mixer library used to generate Proof of Deposit
*/

#include "mixer.hpp"
#include "export.hpp"
#include "import.hpp"
#include "stubs.hpp"
#include "utils.hpp"

// handmade gadgets
#include "gadgets/sha256_eth_fields.hpp"

// ethsnarks gadgets
#include "gadgets/mimc.hpp"
#include "gadgets/merkle_tree.cpp"

using ethsnarks::FieldT;
using ethsnarks::ppT;
using ethsnarks::ProtoboardT;
using ethsnarks::ProvingKeyT;
using libsnark::generate_r1cs_equals_const_constraint;
using json = nlohmann::json;

const size_t MIXER_TREE_DEPTH = 15;

namespace ethsnarks
{


struct mixer_witness
{
    FieldT root;
    FieldT wallet_address;
    FieldT nullifier;
    FieldT nullifier_secret;
    libff::bit_vector address_bits;
    std::vector<FieldT> path;

    /**
    * Construct the witness from a JSON representation of its proof inputs
    */
    static struct mixer_witness fromJSON( const char *in_json )
    {
        const auto json_root = json::parse(in_json);
        const auto arg_root = ethsnarks::parse_FieldT(json_root.at("root"));
        const auto arg_wallet_address = ethsnarks::parse_FieldT(json_root.at("wallet_address"));
        const auto arg_nullifier = ethsnarks::parse_FieldT(json_root.at("nullifier"));
        const auto arg_nullifier_secret = ethsnarks::parse_FieldT(json_root.at("nullifier_secret"));

        const auto arg_path = ethsnarks::create_F_list(json_root.at("path"));
        if( arg_path.size() != MIXER_TREE_DEPTH )
        {
            std::cerr << "Path length doesn't match tree depth" << std::endl;
            abort();
            //return nullptr;
        }

        // Fill address bits from integer
        unsigned long address = json_root.at("address").get<decltype(address)>();
        assert( (sizeof(address) * 8) >= MIXER_TREE_DEPTH );
        libff::bit_vector arg_address_bits;
        arg_address_bits.resize(MIXER_TREE_DEPTH);
        for( size_t i = 0; i < MIXER_TREE_DEPTH; i++ )
        {
            arg_address_bits[i] = (address & (1u<<i)) != 0;
        }

        return {
            arg_root,
            arg_wallet_address,
            arg_nullifier,
            arg_nullifier_secret,
            arg_address_bits,
            arg_path
        };
    }
};


class mod_mixer : public GadgetT
{
public:
    typedef MiMC_hash_gadget HashT;
    typedef Sha256EthFields Sha256HashT; // SHA256 - for commitment
    const size_t tree_depth = MIXER_TREE_DEPTH;

    // public inputs
    const VariableT root_var;
    const VariableT wallet_address_var;
    const VariableT nullifier_var;

    // public constants
    const VariableArrayT m_IVs; // merkle tree's IVs

    // constant inputs
    const VariableT nullifier_hash_IV;
    const VariableT leaf_hash_IV;

    // private (i.e. secret) inputs
    const VariableT nullifier_secret_var; // preimage of the nullifier
    const VariableArrayT address_bits;
    const VariableArrayT path_var;

    // logic gadgets
    HashT nullifier_hash;
    // HashT leaf_hash;
    Sha256HashT leaf_hash;
    merkle_path_authenticator<HashT> m_authenticator;

    mod_mixer(
        ProtoboardT &in_pb,
        const std::string &annotation_prefix) : GadgetT(in_pb, annotation_prefix),

                                                // public inputs
                                                root_var(make_variable(in_pb, FMT(annotation_prefix, ".root_var"))),
                                                wallet_address_var(make_variable(in_pb, FMT(annotation_prefix, ".wallet_address_var"))),
                                                nullifier_var(make_variable(in_pb, FMT(annotation_prefix, ".nullifier_var"))),

                                                // Initialisation vector for merkle tree
                                                // Hard-coded constants
                                                // Means that H('a', 'b') on level1 will have a different output than the same values on level2
                                                m_IVs(merkle_tree_IVs(in_pb)),

                                                // constant inputs
                                                nullifier_hash_IV(make_variable(in_pb, FMT(annotation_prefix, ".spend_hash_IV"))),
                                                leaf_hash_IV(make_variable(in_pb, FMT(annotation_prefix, ".leaf_hash_IV"))),

                                                // private inputs
                                                nullifier_secret_var(make_variable(in_pb, FMT(annotation_prefix, ".spend_preimage_var"))),
                                                address_bits(make_var_array(in_pb, tree_depth, FMT(annotation_prefix, ".address_bits"))),
                                                path_var(make_var_array(in_pb, tree_depth, FMT(annotation_prefix, ".path"))),

                                                // logic gadgets
                                                nullifier_hash(in_pb, nullifier_hash_IV, {nullifier_secret_var, nullifier_secret_var}, FMT(annotation_prefix, ".spend_hash")),
                                                // leaf_hash(in_pb, leaf_hash_IV, {nullifier_secret_var, wallet_address_var}, FMT(annotation_prefix, ".leaf_hash")),
                                                leaf_hash(in_pb, nullifier_secret_var, wallet_address_var, FMT(annotation_prefix, ".leaf_hash")),
                                                m_authenticator(in_pb, tree_depth, address_bits, m_IVs, leaf_hash.result(), root_var, path_var, FMT(annotation_prefix, ".authenticator"))
    {
        in_pb.set_input_sizes(3);

        // TODO: verify that inputs are expected publics
    }

    void generate_r1cs_constraints()
    {
        nullifier_hash.generate_r1cs_constraints();
        leaf_hash.generate_r1cs_constraints();
        m_authenticator.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(nullifier_var, 1, nullifier_hash.result()),
            FMT(annotation_prefix, ".nullifier_var == nullifier_hash"));
    }

    void generate_r1cs_witness(const mixer_witness& witness)
    {
        // public inputs
        this->pb.val(root_var) = witness.root;
        this->pb.val(wallet_address_var) = witness.wallet_address;
        this->pb.val(nullifier_var) = witness.nullifier;

        // private inputs
        this->pb.val(nullifier_secret_var) = witness.nullifier_secret;
        address_bits.fill_with_bits(this->pb, witness.address_bits);

        assert( witness.path.size() == tree_depth );
        for (size_t i = 0; i < tree_depth; i++)
        {
            this->pb.val(path_var[i]) = witness.path[i];
        }

        // gadgets
        nullifier_hash.generate_r1cs_witness();
        leaf_hash.generate_r1cs_witness();
        m_authenticator.generate_r1cs_witness();
    }
};


} // namespace ethsnarks

size_t mixer_tree_depth(void)
{
    return MIXER_TREE_DEPTH;
}


static char* mixer_prove_internal(
    const char *pk_file,
    const ethsnarks::mixer_witness& witness
)
{
    ProtoboardT pb;
    ethsnarks::mod_mixer mod(pb, "module");
    mod.generate_r1cs_constraints();
    std::cout << "Number of constraints for Hopper: " << pb.num_constraints() << std::endl;

    mod.generate_r1cs_witness(witness); //arg_root, arg_wallet_address, arg_nullifier, arg_nullifier_secret, address_bits, arg_path);

    if (!pb.is_satisfied())
    {
        std::cerr << "Not Satisfied!" << std::endl;
        return nullptr;
    }

    auto json = ethsnarks::stub_prove_from_pb(pb, pk_file);

    return ::strdup(json.c_str());
}


char *mixer_prove_json( const char *pk_file, const char *in_json )
{
    ppT::init_public_params();
    const ethsnarks::mixer_witness witness = ethsnarks::mixer_witness::fromJSON(in_json);
    return mixer_prove_internal(pk_file, witness);
}


char *mixer_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_wallet_address,
    const char *in_nullifier,
    const char *in_nullifier_secret,
    const char *in_address, // [LSB...MSB] with regard to bits of index
    const char **in_path)
{
    // std::cout << "ENTERING mixer_prove" << std::endl;
    // std::cout << "pk_file: " << pk_file << std::endl;
    // std::cout << "in_root: " << in_root << std::endl;
    // std::cout << "in_wallet_address: " << in_wallet_address << std::endl;
    // std::cout << "in_nullifier: " << in_nullifier << std::endl;
    // std::cout << "in_nullifier_secret: " << in_nullifier_secret << std::endl;
    // std::cout << "in_address: " << in_address << std::endl;
    // std::cout << "in_path: " << std::endl
    //           << "[";
    // for (size_t j = 0; in_path[j] != nullptr; j++)
    // {
    //     std::cout << " \"" << in_path[j];
    //     if (in_path[j + 1] == nullptr)
    //     {
    //         std::cout << "\"]" << std::endl;
    //     }
    //     else
    //     {
    //         std::cout << "\"," << std::endl;
    //     }
    // }

    ppT::init_public_params();

    FieldT arg_root(in_root);
    FieldT arg_wallet_address(in_wallet_address);
    FieldT arg_nullifier(in_nullifier);
    FieldT arg_nullifier_secret(in_nullifier_secret);

    // Fill address bits with 0s and 1s from str
    libff::bit_vector address_bits;
    address_bits.resize(MIXER_TREE_DEPTH);
    if (strlen(in_address) != MIXER_TREE_DEPTH)
    {
        std::cerr << "Address length doesnt match depth" << std::endl;
        return nullptr;
    }
    for (size_t i = 0; i < MIXER_TREE_DEPTH; i++)
    {
        if (in_address[i] != '0' and in_address[i] != '1')
        {
            std::cerr << "Address bit " << i << " invalid, unknown: " << in_address[i] << std::endl;
            return nullptr;
        }
        address_bits[i] = '0' - in_address[i];
    }

    // Fill path from field elements from in_path
    std::vector<FieldT> arg_path;
    arg_path.resize(MIXER_TREE_DEPTH);
    for (size_t i = 0; i < MIXER_TREE_DEPTH; i++)
    {
        assert(in_path[i] != nullptr);
        arg_path[i] = FieldT(in_path[i]);
    }

    const ethsnarks::mixer_witness witness = {
        arg_root,
        arg_wallet_address,
        arg_nullifier,
        arg_nullifier_secret,
        address_bits,
        arg_path
    };

    return mixer_prove_internal(pk_file, witness);
}

int mixer_genkeys(const char *pk_file, const char *vk_file)
{
    return ethsnarks::stub_genkeys<ethsnarks::mod_mixer>(pk_file, vk_file);
}

bool mixer_verify(const char *vk_json, const char *proof_json)
{
    return ethsnarks::stub_verify(vk_json, proof_json);
}
