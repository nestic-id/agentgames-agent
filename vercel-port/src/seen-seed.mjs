// Seed for the seen-set, migrated from the local agent era (R01-R03 +
// local practice) — file ~/workspace/agentgames/agent/data/seen-proof-tx.json
// as of 16 Nov 2026. The Vercel Blob store (nestic-1-seen) started empty
// at deploy time (16 Nov ~02:16 WIB), so PROOF_REUSED traps referencing
// pre-Vercel approvals were missed (practice session 5, GK2:
// 0x4d84c5e935804315ab0ca81dbbacad26). These entries are a truth source
// consulted before/alongside any backend; all values are lowercased hex
// proof_tx hashes (case-insensitive by nature, matching BlobSeen).
export const SEED_ACCEPTED = [
  "0x4d84c5e935804315ab0ca81dbbacad26",
  "0xe5e892fb24bf83cec3a75deb5e3525b2",
  "0x12ed60a9e7c807a159bdc928396cc179",
  "0x0c757060b81f85704e3305a054857244",
  "0x1923f7245c28d6531df2dbbe23f94b3f",
];
export const SEED_ALL = [
  "0x7fa1a46eb7884ae4b1fb69e61b1e0d50",
  "0x0fdaa11474674f76acce7726b26c6e3e",
  "0x50a502537b9a4e5693a22833237236ea",
  "0x4d84c5e935804315ab0ca81dbbacad26",
  "0x2a3834dd25d940859288875e8fb4dcad",
  "0x38b57d3a8e804710814997be5e3aa4c8",
  "0xcefd6082d64e498cb4ecf00f2e7341bf",
  "0x592f5d2aa1d74ef8a4e93ccc52008b85",
  "0x3d3eb988478f4a169ef227dd0282a56c",
  "0x4e41fbb70b5e49769f49411f4abeccca",
  "0xe5e892fb24bf83cec3a75deb5e3525b2",
  "0x09a92ba3c3bc4960be38353fa17ca8a7",
  "0x12ed60a9e7c807a159bdc928396cc179",
  "0x0c757060b81f85704e3305a054857244",
  "0xfd7c4b422e982c61ac376462e7bb3711",
  "0x53c99696154b05d0f7e70030d8938a31",
  "0x1923f7245c28d6531df2dbbe23f94b3f",
  "0xff577b87f94c42979e769f323b274315",
  "0xeb88a6f1d07d4a3d94eea7cd7e61f530",
];
