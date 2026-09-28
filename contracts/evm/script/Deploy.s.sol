// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.26;
import {Script, console} from "forge-std/Script.sol";
import {AvelockPersonalVault} from "../src/AvelockPersonalVault.sol";
/// @notice Full deployment for chains without the clone factory: the broadcaster
///         is the owner, and the receipt creates and binds the wallet and its
///         module in one transaction. Elsewhere the app uses AvelockVaultFactory.
contract DeployScript is Script {
    function run() external returns (AvelockPersonalVault receipt) {
        uint256 key = vm.envUint("PRIVATE_KEY");
        uint256 withdrawalDelay = vm.envOr("WITHDRAWAL_DELAY", uint256(1 days));
        uint256 addressDelay = vm.envOr("ADDRESS_DELAY", uint256(7 days));
        uint256 confirmationWindow = vm.envOr("CONFIRMATION_WINDOW", uint256(1 days));
        uint256 policyDelay = vm.envOr("POLICY_DELAY", uint256(7 days));
        uint256 minWithdrawalDelay = vm.envOr("MIN_WITHDRAWAL_DELAY", uint256(1 days));
        uint256 minAddressDelay = vm.envOr("MIN_ADDRESS_DELAY", uint256(1 days));
        vm.startBroadcast(key);
        receipt = new AvelockPersonalVault(
            withdrawalDelay, addressDelay, confirmationWindow, policyDelay, minWithdrawalDelay, minAddressDelay
        );
        vm.stopBroadcast();
        require(receipt.owner() == vm.addr(key), "Owner mismatch");
        console.log("Receipt:", address(receipt));
        console.log("Wallet:", address(receipt.wallet()));
        console.log("Security module:", address(receipt.extension()));
    }
}
