# TITANX Security Review

A security review of the [TITANX](https://app.titanx.win/mine) smart contract protocol was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | TITANX                                                                                       |
| Repository    | https://github.com/jakesharpe777/ttx_private/                                                |
| Commit hash   | [1ae0b1359d4b6fc4ca193a5a6dedc43693515a78](https://github.com/jakesharpe777/ttx_private/tree/1ae0b1359d4b6fc4ca193a5a6dedc43693515a78) |
| Documentation | [link](https://docs.titanx.win/titanx/titan-x/titanx.win-pumpamentals)                                 |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   1 |
| High risk     |       1 |
| Medium risk   |     2 |
| Low risk      |       N/A |
| Informational | N/A |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (6)_                                                  |
| /TITANX.sol |
| /BurnInfo.sol |
| /GlobalInfo.sol |
| /MintInfo.sol |
| /StakeInfo.sol |
| /BuyAndBurn.sol |

# Findings

## Critical Severity

### [C-01] Due to unchecked overflow, user can mint themselves infinite TITANX tokens.

#### **Description**

Upon burning their tokens, users can manually input `userRebatePercentage` and  `rewardPaybackPercentage`. These values are respective burn rewards for the user/ dev team upon any tokens burnt. The current limitation is their sum must not exceed 8%. However, since the two values are summed in an unchecked block, this allows using such values that their sum overflows and wrongfully passes the 8% check. Due to the overflow, user can input ridiculously high `rewardPaybackPercentage` and basically mint themselves infinite tokens.
```solidity
        uint maxRewardPercent;
        unchecked {
            maxRewardPercent = rewardPaybackPercentage + userRebatePercentage;
        }
        if (maxRewardPercent > MAX_BURN_REWARD_PERCENT) revert TitanX_InvalidBurnRewardPercent();
```
```solidity
        unchecked {
            if (rewardPaybackPercentage != 0)
                devFee = (amount * rewardPaybackPercentage * PERCENT_BPS) / (100 * PERCENT_BPS);
            if (userRebatePercentage != 0)
                userRebate = (amount * userRebatePercentage * PERCENT_BPS) / (100 * PERCENT_BPS);
        }

        if (devFee != 0) _mint(rewardPaybackAddress, devFee);
        if (userRebate != 0) _mint(user, userRebate);
```

#### **Recommended Mitigation Steps**

Remove the unchecked scope.

#### **Remark**

Fixed by removing the unchecked scope 

## High severity

### [H-01] When EAABonus drops to 0, base reward is also lost.

#### **Description**

When calculating a user's mint reward, early minters have a special EAABonus on top of their reward. Its idea is to give a bonus to early users of the protocol. It linearly decreases over time until it reaches 0. However, due to faulty implementation, when the bonus reaches 0, `baseReward` is also lost.

```solidity
            if (EAABonus != 0) {
                //EAA Bonus has 1e6 scaling, so here divide by 1e6
                reward = baseReward + ((baseReward * EAABonus) / 100 / SCALING_FACTOR_1e6);
            }
```
#### **Recommended Mitigation Steps**
Modify the code in the following way:
```solidity
+           reward = baseReward;
            if (EAABonus != 0) {
                //EAA Bonus has 1e6 scaling, so here divide by 1e6
                reward += ((baseReward * EAABonus) / 100 / SCALING_FACTOR_1e6);
            }
```

#### **Remark**

Fixed as shown above

## Medium severity

### [M-01] If the UniswapV3 pool has over 10% price deviation prior to the BuyNBurn position mint, it will be impossible to mint the position.

#### **Description**
After the `BuyAndBurn.sol` contract receives enough ETH in fees from the `TITANX` contract, it mints a position in the `TITANX/ WETH` at a priorly specified rate. The specified allowed slippage currently set is 10%, meaning that at the time of minting the position, if the price has a deviation of over 10%, position will be impossible to be minted. Considering the Univ3 pool could be created by anyone and will likely have liquidity prior the position being minted, its price can in no circumstances be predicted this exactly. As the `BuyAndBurn` plays a significant role in the ecosystem, such risk should not be neglected.

```solidity
        INonfungiblePositionManager.MintParams
            memory params = INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: POOLFEE1PERCENT,
                tickLower: MIN_TICK,
                tickUpper: MAX_TICK,
                amount0Desired: amount0Desired,
                amount1Desired: amount1Desired,
                amount0Min: (amount0Desired * 90) / 100,
                amount1Min: (amount1Desired * 90) / 100,
                recipient: address(this),
                deadline: block.timestamp + 600
            });

        (uint256 tokenId, uint256 liquidity, , ) = INonfungiblePositionManager(
            NONFUNGIBLEPOSITIONMANAGER
        ).mint(params);
```

#### **Recommended Mitigation Steps**
Upon minting the position, set both `amount0Min` and `amount1Min` to significantly lower numbers, to make sure position mint will be possible.

#### **Remark**

Acknowledged. Situation above is only possible if the needed ETH for the position isn't collected on day 1, which is highly unlikely.

### [M-02] Users may lose their rewards due to unsafe downcasting to uint64 in `_calculateCycleRewardPerShare`

#### **Description**
Each cycle users are allocated rewards based on their shares. At the end of a cycle, `payoutPerShare` is calculated, based on the current active shares. It must be noted, that `payoutPerShare` is scaled up by 1e18. uint64 max value is ~1.8e19, meaning that `payoutPerShare` could realistically exceed this value and be wrongfully downcasted, resulting in serious loss of funds for the users. The funds will be irretrievable and forever stuck within the contract.

Note: the main risk of the issue is in the early days of the project, where a lot of funds will be coming in, and most people will still be minting their tokens and very few will actually hold stake/ have shares.


#### **Recommended Mitigation Steps**
Either scale up the `payoutPerShare` by a smaller number (e.g. 1e12), or downcast it to a larger type (e.g. uint96)

#### **Remark**

Fixed up by changing `payoutPerShare` to uint256

