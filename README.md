# Tractor
Tractor is a generalized system for EIP-712 signing and verification on the EVM. Code can be trivially implemented by
independent protocols.

## Warning
Code is currently untested. Typescript tests have not been updated to work with architecture changes.

## Security Considertions
- Signature Malleability: https://github.com/kadenzipfel/smart-contract-vulnerabilities/blob/master/vulnerabilities/signature-malleability.md, https://twitter.com/gogotheauditor/status/1611667787759616000?s=20
tldr: one set of signer + address can be valid with many signatures that are easy to generate given one example signature

## Credit
Much of the code was inspired and sourced written from [Beanstalk and beam00n](https://github.com/BeanstalkFarms/Beanstalk/pull/154).
