import {NetworkProvider} from '@ton/blueprint';
import {toNano} from '@ton/core';
import {AvelockWallet} from '../build/AvelockWallet/AvelockWallet_AvelockWallet';
import {AvelockSecurityExtension} from '../build/AvelockSecurityExtension/AvelockSecurityExtension_AvelockSecurityExtension';
/** OWNER_PUBLIC_KEY is the app-derived public key. Never pass a mnemonic to this script.
 *  Optional WITHDRAWAL_DELAY/ADDRESS_DELAY/CONFIRMATION_WINDOW/POLICY_DELAY/
 *  MIN_WITHDRAWAL_DELAY/MIN_ADDRESS_DELAY (seconds) override the default
 *  1d/7d/1d/7d/1d/1d initial policy — e.g. for a Deep Vault started at a
 *  stricter config instead of weakening/strengthening its way there later. */
export async function run(provider: NetworkProvider) {
    const key = process.env.OWNER_PUBLIC_KEY;
    if (!key || !/^[0-9a-fA-F]{64}$/.test(key)) throw new Error('OWNER_PUBLIC_KEY must be 32-byte hex');
    const network = provider.network();
    if (network !== 'testnet' && network !== 'mainnet') throw new Error('Choose testnet or mainnet explicitly.');
    const networkId = network === 'testnet' ? -3n : -239n;
    const owner = BigInt('0x' + key);
    const envSeconds = (name: string, fallback: bigint) => process.env[name] ? BigInt(process.env[name]!) : fallback;
    const withdrawalDelay = envSeconds('WITHDRAWAL_DELAY', 86400n);
    const addressDelay = envSeconds('ADDRESS_DELAY', 604800n);
    const confirmationWindow = envSeconds('CONFIRMATION_WINDOW', 86400n);
    const policyDelay = envSeconds('POLICY_DELAY', 604800n);
    const minWithdrawalDelay = envSeconds('MIN_WITHDRAWAL_DELAY', 86400n);
    const minAddressDelay = envSeconds('MIN_ADDRESS_DELAY', 86400n);
    const wallet = provider.open(await AvelockWallet.fromInit(
        owner, networkId, withdrawalDelay, addressDelay, confirmationWindow, policyDelay,
        minWithdrawalDelay, minAddressDelay,
    ));
    const extension = provider.open(await AvelockSecurityExtension.fromInit(
        owner, networkId, wallet.address, withdrawalDelay, addressDelay, confirmationWindow, policyDelay,
        minWithdrawalDelay, minAddressDelay,
    ));
    // Do not spend again on a previously initialized component when resuming setup.
    if (!await provider.isContractDeployed(wallet.address)) {
        await wallet.send(provider.sender(), {value:toNano('0.05')}, null);
        await provider.waitForDeploy(wallet.address);
    }
    if (!await provider.isContractDeployed(extension.address)) {
        await extension.send(provider.sender(), {value:toNano('0.2')}, null);
        await provider.waitForDeploy(extension.address);
    }
    if (!await wallet.getIsExtension(extension.address) || await extension.getOwnerPublicKey() !== owner || await extension.getNetworkGlobalId() !== networkId) throw new Error('Protection verification failed');
    console.log('Verified wallet:',wallet.address.toString());
    console.log('Operational gas address:',extension.address.toString());
}
