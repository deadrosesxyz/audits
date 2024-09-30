# Volt Security Review

A security review of the Volt protocol's smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | Volt                                                                                       |
| Repository    | https://github.com/Kuker-Labs/volt-contracts/                                             |
| Commit hash   | [731dc18e911e76e96eb561de59e323d4f31b9fae](https://github.com/Kuker-Labs/volt-contracts/tree/731dc18e911e76e96eb561de59e323d4f31b9fae) |
| Documentation | NaN                                |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0|
| High risk     |       2|
| Medium risk   |     1 |
| Low risk      |       3 |
| Informational |  |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (5)_                                                  |
| /Constants.sol |
| /TheVolt.sol |
| /Volt.sol |
| /VoltAuction.sol |
| /VoltBuyAndBurn.sol |


# Findings


## High severity

### [H-01] Unsafe casting causes silent overflow when calculating `INTERVALS_PER_DAY`

#### **Description**

When calculating the `INTERVALS_PER_DAY`, the constant is assigned as follows:

```solidity
uint16 constant INTERVAL_TIME = 5 minutes;
uint8 constant INTERVALS_PER_DAY = uint8(24 hours / INTERVAL_TIME);
```

The problem is that the calculation results in 288 intervals, but it is assigned to a uint8, which has a max value of 255. Because of this, it silently overflows and `INTERVALS_PER_DAY` is instead assigned a value of 33.

This later breaks distribution and leads to significantly more funds being distributed than supposed to.

#### **Recommended Mitigation Steps**
Change `INTERVALS_PER_DAY` to uint16.


### [H-02] `_updateSnapshot` is not called daily, although it should be.

#### **Description** 

Ideally, every day `_updateSnapshot` should be called in order for daily distribution to be calculated based on the contract's `titanX` balance at that timestamp. 

However, this is accidentally left out and a snapshot is made only upon the first call. Because of this, all further distributions will be based on the balance the contract has had at the first call.


#### **Recommended Mitigation Steps**
Snapshot the balance daily.


## Medium severity

### [M-01] Wrong value will be snapshotted if `buyandburn` is called in the middle of the day

If `buyAndBurn` is called in the middle of the day, it will first distribute the funds thus far and then snapshot the remaining for the rest of the day. The problem is that these funds do not include the ones which were already distributed for the day thus far. Because of it, the intervals later in that same day will receive less distribution than supposed to.

Note: this issue was introduced with the fix of [H-02]

#### **Recommended Mitigation Steps**
When distributing funds throughout multiple days, whenever the current day is entereed, cache the remaining funds.


## Low Severity

### [L-01] If first swap happens over a day after start time, all distribution will happen based om the day the function is called 

#### **Description**
Currently, the code assumes that the first swap always happens in the same day of the start and bases the distrubiton on that. However, if it does not happen in that same day, distribution will be off.

Due to the low likelihood of not a single swap occuring in the first day, issue is of Low severity.


### [L-02] If LP position is not minted on the first day, users could DoS it.

#### **Description**

If LP position is not minted on the first day, users could gain `Volt` tokens and initialize the pool and add liquidity to any price they wish. Then, if the price they've chosed is outside of the accepted deviation set by the `Volt` contracts, attempting to create the LP position will fail.

Because of the low probability of the LP position not being minted on the first day, issue remains low severity.


### [L-03] If upon start, call is not made within the first interval, funds will be distributed for 1 interval in advance.

During the first swap within the `buyAndBurn`, the contract assumes first call will happen within the first interval. However, if it does not, it will wrongly distribute funds for 1 interval in advance.

