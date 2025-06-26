# HLP0 Security Review

A security review of the HLP0's smart contracts was done by [deadrosesxyz](https://twitter.com/deadrosesxyz). \
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
| Project Name  | HLP0                                                                                     |
| Repository    | https://github.com/hlp0to/hlp0-contracts                                                |
| Commit hash   | [d29208a9ac471a76506b1a2d480c83d80c07fd48](https://github.com/hlp0to/hlp0-contracts/tree/d29208a9ac471a76506b1a2d480c83d80c07fd48) |
| Documentation | NaN                                |
| Methods       | Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| Critical risk |   0|
| High risk     |       0 |
| Medium risk   |     0 |
| Low risk      |       3 |
| Informational | 3 |

### Scope

| File                                                                                                    | 
| :------------------------------------------------------------------------------------------------------ | 
| _Contracts (4)_                                                  |
| /HLP0.sol |
| /HLP0Implementation.sol |
| /HLPSHARES.sol |
| /HLPUSDC.sol |


# Findings


## Low severity

### [L-01] Debase cannot reduce the ratio below 1.

#### **Description**

When HLP has taken a loss, the oracle provider is expected to report it via `debase`. The function currently has a sanity check which disallows reporting a rate below one. This practically means that the rate can never fall below the one at which the contract was initialized. 

As HLP has historically never had major drawdowns, this makes the likelihood of an issue occurring even lower. And in case it does, the contract is upgradeable. 

```solidity
    function debase(uint256 _burnAmount) external OnlyOracleProvider {
        Storage storage $ = getStorage();
        uint256 oldRatio = ratio();
        $.HLPUSDC.burn(_burnAmount);
        require(ratio() >= 1e6, "RATIO BELOW 1.0");
        $.lastOracleUpdate = block.timestamp; 
        uint256 newRatio = ratio();
        emit Debase(_burnAmount, oldRatio, newRatio);
    }
```


#### **Recommended Mitigation Steps**
Remove the sanity check. Consider adding a maximum deviation between individual rebases/debases instead.

#### **Remark**
Acknowledged.

### [L-02] Vault might be susceptible to MEV

#### **Description** 

Currently, an oracle provider needs to regularly provide the price of HLP. This means that the price will always be outdated for a certain period of time, while users could directly get the true price themselves. 

If the price is updated, for example, every 30 minutes, 29 minutes since the last update, a user might deposit in the vault at the outdated (lower) price and request a withdraw immediately after the price update for a quick profit.

Given that withdraws do not happen atomically and require a trusted party to execute them, this leaves the potential attacker without their funds for unknown time. For this reason, the likelihood of a MEV bot attempting such attack is rather low.


#### **Recommended Mitigation Steps**
Either take a small deposit fee or make the deposit process two-step - with the deposits executing at the next price update

#### **Remark**
Acknowledged.

### [L-03] Redeeming locks in the share rate at the time of creation which leads to excessive gains/ losses to the rest of the stakers.

#### **Description** 

Whenever a user wants to withdraw their funds, they have to first create a withdraw request. When doing that, they lock in the current HLP0 rate. However, at that time, their part of the funds is still within the HLP0 vault, which means that if they earn/ lose any money, this will affect the other users who have currently staked in the vault.

```solidity
    function requestRedeem(uint256 _amountOfHLP) external nonReentrant StaleDataCheck {
        uint256 expectedOutput = previewRedeem(_amountOfHLP);
        require(expectedOutput >= MIN_REDEEM_AMOUNT, "MIN_AMOUNT not met");
        
        Storage storage $ = getStorage();
        
        /// @dev burn the HLP0 tokens
        _burn(msg.sender, _amountOfHLP);
        /// @dev burn the equivalent HLPSHARES for ERC4626 accounting
        $.HLPSHARES.burn(_amountOfHLP);
        /// @dev burn the equivalent HLPUSDC backing
        $.HLPUSDC.burn(expectedOutput);
        
        RequestDetails memory request = RequestDetails({
            requestor: msg.sender,
            hlpAmount: _amountOfHLP,
            requestAmount: expectedOutput,
            requestTime: block.timestamp,
            isProcessed: false
        });
        $.requestMapping[$.newRequestId] = request;
        $.newRequestId++;
        /// @dev emit the request submitted event
        emit RequestSubmitted(request, $.newRequestId - 1);
    }
```

#### **Recommended Mitigation Steps**
Instead of locking in the rate at the time the request is created, use the rate at the time when the request is processed.

#### **Remark**
Acknowleged.


## Informational

### [INFO-01] Typo in `requestRedeem`

When requesting a redeem, the input variable is currently named `_amountOfHLP`. However, what's actually meant is amount of HLP0. Since HLP0 and HLP will not be trading 1:1, this might leave some users/ devs confused.

### [INFO-02] `processRequest` can be called on a not yet created request.

#### **Description**
The function does not check whether the request has actually been created. No real impact, as when the request is in fact created, the storage will be overwritten.

### [INFO-03] Governance cannot change the contract owner

#### **Description**

The HLP0 contract is Ownable, with the owner role responsible for the LayerZero bridging. Governance is expected to have full control over the vault, but they're not actually able to change the owner of the contract. As the contract is upgradeable, this is only an informational issue.

