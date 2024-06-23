# Titan Blaze Security Review

A security review of the Titan Blaze protocol's smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | Titan Blaze                                                                                       |
| Repository    | https://github.com/ShintoSan/blaze-contract/blob/diamond-hand                                                |
| Commit hash   | [e61ae9c9dc142bcba51db7e0b2d3bd72afe8e675](https://github.com/ShintoSan/blaze-contract/tree/81da657bf6dfc0e1d08af91a6d183a875172f336) |
| Documentation | NaN                                |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0|
| High risk     |       4 |
| Medium risk   |     1 |
| Low risk      |       0 |
| Informational | 3 |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (8)_                                                  |
| /BlazeAuction.sol |
| /BlazeBonfire.sol |
| /BlazeBurner.sol |
| /BlazeBuyAndBurn.sol |
| /BlazerERC20.sol |
| /DiamondHand.sol |
| /blazeStaking.sol |


# Findings


## High severity

### [H-01] Uniswap swaps lack proper slippage protection

#### **Description**

Both the `BlazeBuyAndBurn` and `BlazeBurner` contracts perform Uniswap swaps. The problem is that the slippage protection they're currently using is insufficient as it relies on the current spot price, which can easily be manipulated (for example, through a flash-loan). `BlazeBuyAndBurn` has a partial protection by using an `onlyEOA` modifier, which would make exploiting this vulnerability a bit harder as of today. Though, with the introduction of `AUTH` and `AUTHCALL` opcodes later this year, this modifier can be bypassed, allowing for any user to be able to steal all of the swapped funds. (For more context, read EIP-3074)

```solidity
    function _swapWETHForTitan(uint256 amountWETH) private dailyUpdate returns (uint256 _titanAmount) {
        (, int256 amount1) = IUniswapV3Pool(TITANX_ETH_POOL).swap(
            address(this),
            true,
            int256(amountWETH),
            MIN_SQRT_RATIO_FOR_TITANX + 1,
            ""
        );
        _titanAmount = uint256(amount1 >= 0 ? amount1 : -amount1);
    }
```

```solidity
    function _swapTitanToBlaze(uint256 amountTitan) private dailyUpdate returns (uint256 _blazeAmount) {
        TransferHelper.safeApprove(TITANX_TOKEN, UNISWAP_V2_ROUTER, amountTitan);
        address[] memory path = new address[](2);
        path[0] = TITANX_TOKEN;
        path[1] = _blazeTokenAddress;
        uint256[] memory outputAmounts=IUniswapV2Router02(UNISWAP_V2_ROUTER).getAmountsOut(
            amountTitan,
            path
        );
        uint256[] memory returnedOutputAmounts=IUniswapV2Router02(UNISWAP_V2_ROUTER).swapExactTokensForTokens(
            amountTitan,
            (outputAmounts[outputAmounts.length-1]*_slippage)/100,
            path,
            address(this),
            block.timestamp+600
        );
        _blazeAmount = returnedOutputAmounts[returnedOutputAmounts.length-1];
    }
```

#### **Recommended Mitigation Steps**
Use Uniswap TWAP oracles to calculate proper slippage protection

#### **Remark**
Fixed. Both UniV2 and UniV3 swaps now use proper slippage protection based on Uniswap TWAP

### [H-02] Attacker can inflate the `currentUsedEthUSDAmount` to brick `buyAndBurn` for the rest of the day

#### **Description** 

Within the `BlazeBuyAndBurn` contract, there's a daily limit in USD of ETH that can be swapped through the contract. The problem is that in order to calculate the swapped ETH, the spot price of ETH is used at the time of swap, which as mentioned above can easily be manipulated. An attakcer might do this every day to arbitrarily inflate the ETH price to make it seem as the limit has been reached, when in reality a much lower amount of ETH has been swapped. 

```solidity
    function getEthPrice() public view returns (uint256) {
        (uint160 sqrtPrice, , , , , , ) = IUniswapV3Pool(ETH_USDC_POOL).slot0();
        address token0 = IUniswapV3Pool(ETH_USDC_POOL).token0();
        uint8 decimals = IERC20Metadata(token0).decimals();
        uint256 price = (10 ** (18 - decimals)) / ((sqrtPrice / SQRT_CONSTANT) ** 2);
        return price;
    }
```

#### **Recommended Mitigation Steps**
Use Uniswap TWAP price

#### **Remark**
Fixed as recommended.

### [H-03] User can use the same NFT to participate multiple times in the same `DiamondHand` cycle

#### **Description** 

When users call `participate` within `DiamondHand`, they get tickets based on their `DiamondNFT` balance. The problem is that nothing restricts the users from buying NFTs, calling `participate`, transferring the NFTs to another wallet and repeating the process over and over again. This would allow them to gain more tickets than they should usually be able to, allowing them to steal innocent users' rewards.

#### **Recommended Mitigation Steps**
When calling `participate`, check the NFT ids that have been used and do not allow them to be used again in that same cycle.

#### **Remark**
Fixed on DiamondNFT contract level.

### [H-04] `BlazeBonfire` allows for creating two events on the same date, which would result in permanent DoS within the contract 

#### **Description** 

When `scheduleBonfireEvent` is called, it does not check that new set event is strictly later than the current latest one. This allows for calling `scheduleBonfireEvent` for a date on which an event already exists. The date will be added for the 2nd time to `eventDates`, though the `events` mapping value will be overwritten.

After the bonfire event concludes, the next `eventDate` will be that same date again. Then, since the event has finished, the following `require` check will permanently revert, causing a DoS within the contract 

```solidity
        require(events[currentDate].totalFunds > events[currentDate].fundsBurned, "BlazeBonfire: All funds burned");
```

#### **Recommended Mitigation Steps**
Check that the date set is strictly after the latest one 

#### **Remark**
Fixed. BlazeBonfire now automatically creates an event every 108 days.

## Medium severity

### [M-01] Any user can `idle` in the staking contract to keep receiving rewards even after their stake has finished.

After a user's stake has finished, they remain their shares up until `unstakeBlaze` is called. This allows for a user to unfairly gain rewards for periods in which their tokens are not locked. While this is similar behaviour to TitanX staking, TitanX staking has an increasing fee if a user does not unstake soon after their stake has finished, which incentivizes users to withdraw their funds.

#### **Recommended Mitigation Steps**
Easiest solution would be to keep an off-chain bot which calls `unstakeBlaze` for every stake that has finished.

#### **Remark** 
Acknowledged.

## Informational

### [INFO-01] Remove commented out code

#### **Description**
Within `blazeStaking` there are multiple instances where there's commented out code. As it is not needed, it can simply be removed to increase code readabilty.

```solidity
    // function unstakeBlazeForOthers(address __user, uint256 __id) external dailyUpdate nonReentrant {
    //     uint256 amount = _unstakeBlaze(__user, __id);
    //     IERC20(_blazeToken).safeTransfer(__user, amount);
    // }
```

#### **Remark** 
Fixed.

### [INFO-02] Use the UniswapV3 Router instead of calling the pool directly

#### **Description**

Within `BlazeBurner` and `BlazeBuyAndBurn`, UniswapV3 pool is called directly. This adds unnecessary complexity as it requires adding additional logic which already exists in the battle-tested code of `UniswapV3Router`. Using the Router would make the code cleaner, simpler and safer.

#### **Remark** 
Fixed.

### [INFO-03] Unnecessary usage of `safeTransfer` as only Blaze's own token is used.

Within `blazeStaking`, `safeTransfer` is used instead of simply `transfer`. This is unnecessary as the only used token is Blaze's own token, which is a regular ERC20.

#### **Remark** 
Acknowledged.
