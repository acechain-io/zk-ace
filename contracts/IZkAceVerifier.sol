// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IZkAceVerifier
 * @notice Interface for the ZK-ACE on-chain verifier.
 *
 * @dev Two instances of ZkAceVerifier are deployed — one per replay mode:
 *
 *      NonceRegistry mode:
 *        - rp_com = Poseidon(id_com, nonce)
 *        - Each transaction uses a fresh nonce (similar to EVM account nonce)
 *        - On-chain contract tracks used nonces per identity
 *
 *      NullifierSet mode:
 *        - rp_com = Poseidon(auth, domain)
 *        - Each domain produces a unique, deterministic nullifier
 *        - On-chain contract tracks used nullifiers globally
 *        - Stronger privacy (no nonce sequence linkability)
 *
 *      Public inputs for both modes:
 *        input[0] = id_com   — Identity commitment
 *        input[1] = tx_hash  — Transaction hash being authorized
 *        input[2] = domain   — Chain/application domain
 *        input[3] = target   — Hash of context-derived key material
 *        input[4] = rp_com   — Replay prevention commitment
 */
interface IZkAceVerifier {
    /**
     * @notice Verify a ZK-ACE Groth16 proof.
     *
     * @param a     Proof element A (G1): [x, y]
     * @param b     Proof element B (G2): [x1, x2, y1, y2]
     * @param c     Proof element C (G1): [x, y]
     * @param input Public inputs: [id_com, tx_hash, domain, target, rp_com]
     *
     * @return valid True if the proof is valid.
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[4] calldata b,
        uint256[2] calldata c,
        uint256[5] calldata input
    ) external view returns (bool valid);

    /**
     * @notice Verify a proof and revert if invalid.
     */
    function verifyProofOrRevert(
        uint256[2] calldata a,
        uint256[4] calldata b,
        uint256[2] calldata c,
        uint256[5] calldata input
    ) external view;
}
