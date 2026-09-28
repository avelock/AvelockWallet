// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;

/// @notice A minimal ERC-20-shaped token that never reverts on transfer
///         but always returns false — the exact failure mode a plain
///         low-level `.call` cannot detect on its own (threat-model
///         section 50).
contract MockFalseReturningERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}
