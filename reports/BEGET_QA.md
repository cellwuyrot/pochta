# QA: cabinet / Beget mailbox identities

- Baseline archive: 203 passing tests.
- Updated project: 231 passing tests; Ruff passed.
- 26 added mailbox tests; test cleanup covers the new Mailbox model.
- Desktop/mobile route screenshots inspected individually: cabinet, new mailbox, edit mailbox, empty project, duplicate-address error, provider-managed DNS; mobile expanded menu.
- No horizontal overflow or overlapping controls observed at 1440px / 390px.
- Synthetic preview mailboxes only; secrets/real user mail are not included in archive.
- Interactive browser verification: create mailbox, select sender, queue message, toggle mobile menu. Workers disabled for preview; no external SMTP connections.
- Real Beget credentials, DNS records, deliverability and production Docker deployment were not tested.
- Upgrade helper: shell syntax checked; Docker unavailable in preparation environment.
