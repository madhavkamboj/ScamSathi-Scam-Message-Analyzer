# ScamSathi

ScamSathi is a mobile-friendly Indian scam message analyser that explains suspicious message patterns using transparent, local-only rules.

## Run & Operate

- Use the managed `artifacts/scamsathi: web` workflow to run the app in Replit; it supplies the required `PORT` and `BASE_PATH`.
- To run the dev server manually from the workspace root: `PORT=5173 BASE_PATH=/ pnpm --filter @workspace/scamsathi run dev`
- `pnpm --filter @workspace/scamsathi run typecheck` — typecheck the app
- `pnpm --filter @workspace/scamsathi run test` — run the analyzer regression tests
- `PORT=5173 BASE_PATH=/ pnpm --filter @workspace/scamsathi run build` — build the app
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- The ScamSathi app does not require a database, API, account, or external service.

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React + Vite
- Scam checks run locally in the browser; recent history is stored in local storage.

## Where things live

- `artifacts/scamsathi/` — ScamSathi web app
- `artifacts/api-server/` — shared API server scaffold; ScamSathi does not send analysis data to it.
- `lib/` — shared workspace libraries

## Architecture decisions

- Message analysis is deterministic and client-side; pasted message text is not sent to an external service.
- Analysis history is kept only in the current browser's local storage.

## Product

Users can analyse suspicious messages, review the rule-based warnings and safe next steps, try example messages, and revisit recent local analyses. Risk scores are heuristic estimates, not proof of fraud.

## User preferences

- Keep the app mobile-friendly, use a dark navy cybersecurity theme, and avoid login or personal-data collection.

## Gotchas

- Do not open, follow, or request suspicious URLs during analysis.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
