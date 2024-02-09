# Stream Finance Security Review

A security review of the Stream Finance smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
This audit report includes all the vulnerabilities, issues and code improvements found during the security review.

## Disclaimer

"Audits are a time, resource and expertise bound effort where trained experts evaluate smart
contracts using a combination of automated and manual techniques to find as many vulnerabilities
as possible. Audits can show the presence of vulnerabilities **but not their absence**."

\- Secureum

## Risk classification

| Severity           | Impact: High | Impact: Medium | Impact: Low |
| :----------------- | :----------: | :------------: | :---------: |
| Likelihood: High   |   Critical   |      High      |   Medium    |
| Likelihood: Medium |     High     |     Medium     |     Low     |
| Likelihood: Low    |    Medium    |      Low       |     Low     |

### Impact

- **High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.
- **Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.
- **Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

### Likelihood

- **High** - attack path is possible with reasonable assumptions that mimic on-chain conditions and the cost of the attack is relatively low to the amount of funds that can be stolen or lost.
- **Medium** - only conditionally incentivized attack vector, but still relatively likely.
- **Low** - has too many or too unlikely assumptions or requires a huge stake by the attacker with little or no incentive.

### Actions required by severity level

- **Critical** - client **must** fix the issue.
- **High** - client **must** fix the issue.
- **Medium** - client **should** fix the issue.
- **Low** - client **could** fix the issue.

## Executive summary

### Overview

|               |                                                                                              |
| :------------ | :------------------------------------------------------------------------------------------- |
| Project Name  | Stream Finance                                                                                       |
| Repository    | hhttps://github.com/StreamDefi/streamdefi-contracts/tree/main                                                |
| Commit hash   | [14350bbba798b9df3fc09e9abbe2a5bb192d39f1](hhttps://github.com/StreamDefi/streamdefi-contracts/tree/main/14350bbba798b9df3fc09e9abbe2a5bb192d39f1) |
| Documentation | -                                |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0 |
| High risk     |       0 |
| Medium risk   |     1 |
| Low risk      |       3 |
| Informational | 3 |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (3)_                                                  |
| /StreamVault.sol |
| /ShareMath.sol |
| /Vault.sol |


# Findings

## Medium Severity

### [M-01] If a round ends with only 1 minted share, the attacker can do inflation attack and steal subsequent user funds

#### **Description**

If a round has ended with a very low number of shares (such as 1 wei), the user can do a ERC4626-like inflation attack, by simply directly sending the vault assets. Subsequent user deposits will then round down the minted shares to zero, effectively letting the attacker steal the victims' funds.

```solidity
    function rollToNextRound(
        uint256 currentBalance
    ) external onlyKeeper nonReentrant {
        Vault.VaultState memory state = vaultState;
        uint256 currentRound = state.round;

        uint256 newPricePerShare = ShareMath.pricePerShare(
            totalSupply() - state.queuedWithdrawShares,
            currentBalance - lastQueuedWithdrawAmount,
            state.totalPending,
            vaultParams.decimals
        );

        roundPricePerShare[currentRound] = newPricePerShare;

        vaultState.totalPending = 0;
        vaultState.round = uint16(currentRound + 1);

        uint256 mintShares = ShareMath.assetToShares(
            state.totalPending,
            newPricePerShare,
            vaultParams.decimals
        );

        _mint(address(this), mintShares);
```

#### **Recommended Mitigation Steps**

Upon rolling a round, make sure there's enough shares minted first (e.g. at least 1e4)



## Low severity

### [L-01] Usage of `transfer` instead of `safeTransfer`

#### **Description**

Within `rollToNextRound` when transfering ERC20, regular `transfer` is used, instead of `safeTransfer`. This would lead to 2 problems:
 - Vault is incompatible with ERC20s which do not return `bool` on their `transfer` method
 - If ERC20 does not revert on failure, the `transfer` can silently fail

```solidity
        IERC20(vaultParams.asset).transfer(
            keeper,
            IERC20(vaultParams.asset).balanceOf(address(this)) -
                queuedWithdrawAmount
        );
```
#### **Recommended Mitigation Steps**
Use `safeTransfer`



### [L-02] Unnecessary vault limitations might lead to incompatibility with low-value ERC20s 

#### **Description**

Currently, there are multiple uint limitation accross the codebase, such as a limitation on the total locked value that it cannot exceed `uint104`. In case the vault wants to use a low-value ERC20, uint104 might not be enough as it can hold up to only `~2e29 wei`

#### **Recommended Mitigation Steps**
Remove such `uint` limitations



### [L-03] `accountVaultBalance` and `pricePerShare` do not take into account the queued for withdrawal assets and shares

#### **Description**

Both functions wrongfully calculate a share's price, as they do not subtract the queued for withdrawal shares and assets from the total ammount. This would lead to incorrect price being used. 

Since these are only view functions, which are not used for any internal logic/ accounting, issue is of low severity

#### **Recommended Mitigation Steps**
Fix the formula used to calculate a share's price



## Informational 

### [I-01] Centralization risks

#### **Description**
The keeper can at any time take control of all non-queued for withdrawal funds and do with them as they please. The owner can at any time change the keeper, therefore both roles have signiifcant priviliges which the users should be aware of.



### [I-02] Keeper should be a contract in order to make sure the `currentBalance` input is always correct

#### **Description**
When rolling to next round, the keeper has to manually input the true `currentBalance`. In order the amount is correct, it is advised that the keeper should be a contract and calculate the `currentBalance` directly based on the vault's eth balance



### [I-03] The `totalBalance` of the contract includes the queued for withdrawal funds

#### **Description**
Since the `totalBalance` includes the queued for withdrawals funds, its value will be inflated and it would make it easier to reach the deposit limit, while actually having less funds in `strategy` than expected.

