# Deployment

## Local

```bash
pnpm install
pnpm dev
```

The web app defaults to `http://localhost:3000` and the API defaults to `http://localhost:4000`.

## Provider Configuration

Sui mainnet works with the public GraphQL endpoint by default. Production deployments should configure provider endpoints explicitly:

```bash
SUI_MAINNET_GRAPHQL_URL=https://graphql.mainnet.sui.io/graphql
SOLANA_MAINNET_RPC_URL=https://api.mainnet-beta.solana.com
ETHEREUM_MAINNET_RPC_URL=https://your-ethereum-provider
ETHERSCAN_API_KEY=optional-for-abi-lookups
```

Use `customGraphqlUrl` or `customRpcUrl` only for trusted internal use. Public deployments should validate and allowlist provider endpoints before accepting arbitrary RPC URLs.

## Infrastructure

```bash
docker compose up -d postgres redis
```

PostgreSQL and Redis are included for the production-shaped architecture. The current MVP keeps scan state in memory until migrations and BullMQ wiring are completed.

Restarting the API clears in-memory scan IDs. Persist scan records before exposing packsight as a public service.
