# Helios Security Review

A security review of the Helios smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | Helios                                                                                       |
| Repository    | https://github.com/DudeGuy420/helios-contracts                                               |
| Commit hash   | [978739c0a2dc6e5ef5111011de9b8b6329a472c9](https://github.com/DudeGuy420/helios-contracts/978739c0a2dc6e5ef5111011de9b8b6329a472c9) |
| Documentation | -                                 |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0 |
| High risk     |       5 |
| Medium risk   |     3 |
| Low risk      |       N/A |
| Informational | N/A |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (7)_                                                  |
| /Helios.sol |
| /BurnInfo.sol |
| /GlobalInfo.sol |
| /MintInfo.sol |
| /StakeInfo.sol |
| /BuyAndBurn.sol |
| /Treasury.sol | 

# Findings


## High severity

### [H-01] Lack of slippage protection due to usage of `slot0`

#### **Description**

Within the contract, there are multiple swap instances, where slippage protection is intended to be calculated. Howecer, in order to get the asset's price, `slot0` is used. `slot0` is easily manipulatable and makes slippage protection actually inexistent, allowing for an attacker to steal all funds swapped, by sandwiching the transaction.

```solidity
    function getCurrentTitanPrice() public view returns (uint256) {
        IUniswapV3Pool pool = IUniswapV3Pool(s_poolAddress);
        (uint256 sqrtPriceX96, , , , , , ) = pool.slot0();
        uint256 numerator1 = sqrtPriceX96 * sqrtPriceX96;
        uint256 numerator2 = 10 ** 18;
        uint256 price = FullMath.mulDiv(numerator1, numerator2, 1 << 192);
        price = TITANX < s_hlxAddress ? (1 ether * 1 ether) / price : price;
        return price;
    }
```


#### **Recommended Mitigation Steps**
Use UniswapV3 TWAP oracle to calculate slippage protection

#### **Remark**

Fixed as recommended.

### [H-02] Any TitanX received in Treasury after max stakes are reached will be forever lost.

#### **Description**

Currently, any TitanX received by the Treasury contract is used towards staking it within the TitanX contract. However, there is a limit of stakes an address can have. After the contract reaches max stakes, any further titanx received will be forever stuck.

```solidity
       uint256 startDate = block.timestamp;
        uint256 expirationDate = startDate + (uint256(STAKE_DURATION) * 1 days);

        titanxAmount = getTitanBalance(); // get the treasury titanx balance maybe increased after any stake ended

        //calculate the incentiveFee for this function calling
        uint256 incentiveFee = _calculateIncentiveFee(titanxAmount); // Approve the titanx
        //transfer fee to user
        TransferHelper.safeTransfer(s_titanxAddress, msg.sender, incentiveFee);
        // start staking to titanX protocol
        ITITANX(s_titanxAddress).startStake(
            (titanxAmount - incentiveFee),
            STAKE_DURATION
        );
```


#### **Recommended Mitigation Steps**
Implement a way to get TitanX out of the contract after max stakes are reached.

#### **Remark**

Fixed. New logic was implemented in order to not get TitanX stuck.

### [H-03] In `startStake` the percentage bonus is scaled up by wrong number.

#### **Description**

When staking within the `Helios` contract, the user is calculated a bonus rewards percentage based on the amount of TitanX they wish to burn. However, the bonus percentage is initially scaled up by 1_000, but is later divided by 10_000, resulting in 10 times less bonus percentage.

```solidity
   function calculateBonusPercentage(
        uint256 titanAmount,
        uint256 titanPrice,
        uint256 amountStaked
    ) internal pure returns (uint256) {
        uint256 titanValue = titanAmount * titanPrice;

        uint256 percentage = (((titanValue * SCALING_FACTOR_1e18) /
            (amountStaked * SCALING_FACTOR_1e18)) * 1000) / SCALING_FACTOR_1e18;

        return percentage;
    }
```
```solidity
        if (titanAmount > 0) {
            uint256 percentage = calculateBonusPercentage(
                titanAmount,
                titanPrice,
                amount
            );
            if (percentage > 1000) percentage = 1000;

            shares = shares + ((shares * percentage) / 10000);
        }
```


#### **Recommended Mitigation Steps**
Scale both numbers by the same amount.

#### **Remark**

Fixed as recommended. 

### [H-04] Treasury burns TitanX, but has no way to claim TitanX burn pool rewards.

#### **Description**

The `Treasury` contract burns has a function which burns TitanX. When burning TitanX, protocols are allocated burn shares, which then accrue rewards from the TitanX burn pool. However, the `Treasury` contract lacks a function which claims these rewards.


#### **Recommended Mitigation Steps**
Add a way to claim these rewards.

#### **Remark**

Fixed. `Treasury` contract no longer burns TitanX

### [H-05] Unsafe downcasting results in loss of rewards

#### **Description**

Within `storeMintInfo` a user's mintPower is downcasted to uint8. Since the max `mintPower` can be `100_000`, this is far from enough and will almost always result in downcasting, causing the user loss of funds.

```solidity
        UserMintInfo memory userMintInfo = UserMintInfo({
            mintPower: uint8(mintPower),
            numOfDays: uint16(numOfDays),
            mintableHlx: uint96(mintable),
            mintPowerBonus: uint32(mintPowerBonus),
            EAABonus: uint32(EAABonus),
            mintStartTs: uint48(block.timestamp),
            maturityTs: uint48(block.timestamp + (numOfDays * SECONDS_IN_DAY)),
            mintedHlx: 0,
            mintCost: uint64(mintCost),
            status: MintStatus.ACTIVE
        });
```


#### **Recommended Mitigation Steps**
Remove unnecessary downcasting

#### **Remark**

Fixed. 

## Medium severity

### [M-01] Burning TitanX for mint bonus has negative ROI

#### **Description**

With the current mint formula, the bonus Helios received by burning TitanX is less than what the user could get by simply using the samoe amount of TitanX for new miners.  

```solidity
 function calculateMintReward(
    uint256 mintPower,
    uint256 numOfDays,
    uint256 mintableHlx,
    uint256 EAABonus,
    uint256 burnAmpBonus,
    uint256 percentageBonus
) pure returns (uint256 reward) {
    uint256 baseReward = (mintableHlx * mintPower * numOfDays);
    if (numOfDays != 1)
        baseReward -= (baseReward * MINT_DAILY_REDUCTION * (numOfDays - 1)) / PERCENT_BPS;

    reward = baseReward;
    if (EAABonus != 0) {
        //EAA Bonus has 1e6 scaling, so here divide by 1e6
        reward += ((baseReward * EAABonus) / 100 / SCALING_FACTOR_1e6);
    }

    if (burnAmpBonus != 0) {
        //burnAmpBonus has 1e18 scaling
        reward += (baseReward * burnAmpBonus) / 100 / SCALING_FACTOR_1e18;
    }

    // Apply the percentage bonus
    if (percentageBonus != 0) {
        // Ensure the bonus is within the allowed range (1000 to 2000)
        percentageBonus = percentageBonus > 2000 ? 2000 : percentageBonus;
        // Convert the bonus to a percentage (1000 represents 10%, so divide by 10000)
        uint256 additionalReward = (baseReward * percentageBonus) / 10000;
        reward += additionalReward;
    }

    reward /= MAX_MINT_POWER_CAP;
}
```

#### **Recommended Mitigation Steps**
Change the formula in order to incentivize users to burn TitanX

#### **Remark**

Fixed. Formula changed in a way it is now profitable for users to burn TitanX

### [M-02] Usage of `<` instead of `<=` makes last stake impossible to be claimed.

#### **Description**
Within the `Treasury` contract, after stake reaches maturity, any user can call `endStakeAfterMaturity` and claim the staked TitanX. However, since `<` is used, the user cannot actually call the contract with the last stake id 
```solidity
    function endStakeAfterMaturity(uint256 sId) external {
        ITITANX titanX = ITITANX(TITANX);
        require(sId > 0 && sId < s_lastStakeId, "invalid ID");

        ITITANX.UserStakeInfo memory stakeInfo = titanX.getUserStakeInfo(
            address(this),
            sId
        );

        // End stake if matured
        if (block.timestamp >= stakeInfo.maturityTs) {
            // End the stake
            titanX.endStake(sId);

            //calculate the incentiveFee for this function calling
            uint256 incentiveFee = _calculateIncentiveFee(
                stakeInfo.titanAmount,
                false
            );
            //transfer fee to user
            TransferHelper.safeTransfer(TITANX, msg.sender, incentiveFee);
        } else {
            revert("Stake Not matured");
        }
    }
```

#### **Recommended Mitigation Steps**
Change `<` to `<=`

#### **Remark**
Fixed.

### [M-03] `burnLPTokens` should only be callable by the `BuyAndBurn` contract or it possesses a high centralization risk.

#### **Description**
In the current implementation any user can call `burnLPTokens` and burn all Helios within the current `s_buyandburn` contract. The problem is that the owner can at any time change this value, therefore allowing them to burn any user's funds at any time. This also includes all the funds within the UniswapV3 pool. By doing so, the owner would be able to steal all funds within the UniswapV3 liquidity pool.

```solidity
    function burnLPTokens() external dailyUpdate {
        _burn(s_buyAndBurnAddress, balanceOf(s_buyAndBurnAddress));
    }
```


#### **Recommended Mitigation Steps**
Make the `burnLPTokens` only callable by the current BuyAndBurn contract

#### **Remark**
Fixed.

