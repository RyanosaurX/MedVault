
# MedVault Smart Contract

A secure and decentralized medical records management system built on the Stacks blockchain.

## Overview

MedVault is a smart contract that enables secure storage and controlled sharing of medical records. It implements a comprehensive permission system that allows patients to maintain ownership of their medical data while granting temporary access to healthcare providers.

## Features

- **Secure Record Storage**: Store encrypted medical record hashes on-chain
- **Access Control**: Grant and revoke access to specific healthcare providers
- **Time-Limited Permissions**: Set expiration times for granted access
- **Audit Trail**: Maintain a complete log of all access events
- **Record Ownership**: Transfer record ownership when needed
- **Administrative Controls**: Managed by designated admin for system oversight

## Core Functions

### For Patients

- `add-record`: Add a new medical record
- `update-record`: Update an existing record
- `grant-access`: Give a healthcare provider access to records
- `revoke-access`: Remove a provider's access
- `transfer-ownership`: Transfer record ownership to another principal
- `get-record`: Retrieve record details (owner/authorized only)

### For Healthcare Providers

- `check-access`: Verify current access permissions
- `get-record`: Access patient records (if authorized)
- `update-record`: Update records (if edit permission granted)

### For Administrators

- `change-admin`: Transfer administrative rights

## Data Structures

- **Patient Records**: Stores encrypted data hash, owner, version, and timestamp
- **Access Permissions**: Manages viewer permissions with expiration times
- **Access Logs**: Tracks all record access events

## Error Codes

- `ERR-NOT-AUTHORIZED (u100)`: Unauthorized access attempt
- `ERR-ALREADY-EXISTS (u101)`: Record already exists
- `ERR-DOES-NOT-EXIST (u102)`: Record not found
- `ERR-EXPIRED-ACCESS (u103)`: Access permission expired
- `ERR-INVALID-INPUT (u104)`: Invalid input parameters

## Security Features

- Encrypted data storage
- Time-bound access controls
- Comprehensive access logging
- Owner-only permission management
- Input validation checks

## Development

This contract is developed using Clarity and can be tested using Clarinet. The project includes a test suite in the `/tests` directory.

### Project Structure

```
MedVault/
├── contracts/
│   └── med-vault-contract.clar    # Main contract
├── tests/
│   └── med-vault-contract_test.ts # Test suite
└── settings/
    ├── Devnet.toml               # Development network config
    ├── Testnet.toml             # Test network config
    └── Mainnet.toml             # Production network config
```

## License

This project is proprietary and all rights are reserved.
