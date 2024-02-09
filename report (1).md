# DragonX Security Review

A security review of the DragonX protocol's smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | DragonX                                                                                       |
| Repository    | https://github.com/DragonX2024888/DragonX                                                |
| Commit hash   | [e61ae9c9dc142bcba51db7e0b2d3bd72afe8e675](https://github.com/DragonX2024888/DragonX/tree/e61ae9c9dc142bcba51db7e0b2d3bd72afe8e675) |
| Documentation | NaN                                |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0|
| High risk     |       3 |
| Medium risk   |     0 |
| Low risk      |       3 |
| Informational | 1 |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (6)_                                                  |
| /DragonBuyAndBurn.sol |
| /DragonX.sol |
| /TitanBuy.sol |
| /DragonStake.sol |
| /Constants.sol |

# Findings


## High severity

### [H-01] Incorrect slippage protection when swapping due to using `slot0`

#### **Description**

The `DragonBuyAndBurn` and `TitanBuy` contracts do swaps via Uniswap. In order to prevent sandwich attacks, there's a `minAmountOut` calculated. However, it is based on the `slot0` price which can be manipulated, hence making the slippage protection inexsitent, allowing for a third-party to sandwich the swaps and steal the tokens.

```solidity
    function getCurrentTitanPriceForEth() public view returns (uint256 price) {
        address poolAddress = PoolAddress.computeAddress(
            UNI_FACTORY,
            PoolAddress.getPoolKey(WETH9_ADDRESS, TITANX_ADDRESS, FEE_TIER)
        );
        IUniswapV3Pool pool = IUniswapV3Pool(poolAddress);
        (uint256 sqrtPriceX96, , , , , , ) = pool.slot0();
        uint256 numerator1 = sqrtPriceX96 * sqrtPriceX96;
        uint256 numerator2 = 10 ** 18;
        price = Math.mulDiv(numerator1, numerator2, 1 << 192);

        // Adjust price based on whether WETH is token0 (invert)
        // Addresses are constants, so we can hardcode the calculation
        // price = WETH9 < TitanX ? (1 ether * 1 ether) / price : price;

        price = (1 ether * 1 ether) / price;
    }
```
#### **Recommended Mitigation Steps**
Use UniswapV3 TWAP oracle

#### **Remark**

Fixed by using TWAP oracle.


### [H-02] Upon minting, `genesisVault` values are overwritten, instead of increased

#### **Description** 

Upon minting, 8% of the TitanX and DragonX are allocated towards the `genesisVault`. However, instead of increasing, the amounts are being overwritten upon each mint, leading to permanent loss of funds. 

```solidity
        // Allocate 8% of both TitanX and DragonX to the development team's vault
        _genesisVault[address(this)] = genesisShare;
        _genesisVault[address(titanX)] = genesisShare;
```

#### **Recommended Mitigation Steps**
Change `=` to `+=`

#### **Remark**

Fixed as recommended

### [H-03] After TitanX stake expires, no way to reclaim the TitanX back.

#### **Description** 

After successfully starting a max period stake within the TitanX protocol, DragonX starts earning rewards. However, once the stake ends, the protocol lacks functionality to withdraw the stake, effectively losing the TitanX amount. 


#### **Recommended Mitigation Steps**
Introduce a function which would allow for the withdraw of finished stakes.

#### **Remark**

Fixed by adding functions `endStakeAfterMaturity` and `sendTitanX` to `DragonStake.sol`

## Low severity

### [L-01] `TitanX#triggerPayouts` should be called during `claim` in order to make sure all rewards are claimed. 

#### **Description**
Upon calling `claim` within `DragonX`, all available rewards for the `DragonStake` contracts are claimed. However, in case it's a payout day and `triggerPayouts` hasn't been called, it would be better if `DragonX` calls it, in order to make sure all rewards are claimed. This would further even give the caller an incentive fee for calling `triggerPayouts`


#### **Recommended Mitigation Steps**
Call `TitanX#triggerPayouts` within `claim`

#### **Remark**

Fixed by calling `triggerPayouts` within the `claim` function 

### [L-02] Swaps might fail, if there's a high swap cap, and not enough liquidity in the pool. 

#### **Description**
If the swap caps are too high, and there isn't enough liquidity in the UniswapV3 pool, the swap may cause too high price impact, leading to the transaction reverting because of the slippage protection. In order  for this not to happen, proper initial liquidity should be minted, while also maintaining a reasonable swap cap.

#### **Recommended Mitigation Steps**
Choose appropriate initial liquidity and swap cap

#### **Remark**

Acknowledged. The team will closely monitor the protocol/ UniV3 pool in order to maintain a reasonable swap cap.

### [L-03] Regular stakes should also update `nextStakeTs` 

#### **Description**
Currently, a stake can happen in only 2 occassions - if the vault has over `TITANX_BPB_MAX_TITAN` TitanX or if a stake has been over a week since the last stake of less than `TITANX_BPB_MAX_TITAN`. This would lead for unreasonable cases where only a small amount of TitanX is staked, not utilizing the bigger-pays-better bonus of TitanX staking.

#### **Recommended Mitigation Steps**
Upon each stake update `nextStakeTs`. Allow for stakes of less than `TITANX_BPB_MAX_TITAN` to only occur if there has been no stake whatsoever for over a week. 

#### **Remark**

Fixed as suggested.

## Informational

### [I-01] Centralization risks. 

#### **Description**
Contracts `DragonBuyAndBurn`, `DragonX` and `TitanBuy` are ownable. An owner could modify the parameters of the contract. This includes:
 - Changing the `DragonBuyAndBurn` and `TitanBuy` addresses within `DragonX`
 - Changing the `DragonX` address within `DragonBuyAndBurn` and `TitanBuy`
 - Changing the `capPerSwap`, `slippage`, and BuyAndBurn `interval` within `DragonBuyAndBurn` and `TitanBuy`






