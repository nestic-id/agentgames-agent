# PORT-REPORT — NESTIC-1 Vercel Serverless Port

Dibuat: Senin 16 Nov 2026 (saat Round 03 masih berjalan — agen live TIDAK disentuh).
Metode: SUPERAGENT **sk16** (software engineering: kode runnable, test by default) + **sk53** (deep decomposition: port dipecah menjadi transport core bersama + dua handler verbatim + lapisan proof + seen-store pluggable).
Status: **BUILT + LOCALLY PROVEN. NOT deployed.** Tidak ada deploy, tidak ada push GitHub, endpoint platform tidak diubah, agen live (`~/workspace/agentgames/agent/`, kedua unit systemd) terverifikasi tetap `active` sesudah pekerjaan ini.

## 1. Yang dibangun — `~/workspace/agentgames/vercel-port/`

| File | Isi |
|---|---|
| `api/agent.mjs` | Entry Vercel (persis pola pecker): ekspor Web-standard `POST`/`GET`/`HEAD`. POST membaca raw body → transport core → Response bertanda tangan. |
| `src/handler.mjs` | Transport core bersama: HMAC atas raw body SEBELUM parse (401 bila mismatch) → preflight → routing type-sniff (satu fungsi untuk kedua track, seperti live `POST /agent`) → fail-closed (crash GK → REJECT, Steal → HOLD) → semua respons JSON ditandatangani. |
| `src/gatekeeper.mjs` | `decide()` + handler, diporting dari live `src/gatekeeper.js`. |
| `src/steal.mjs` | `policy()` + `publicInputsHash()` + handler, diporting dari live `src/steal.js`. |
| `src/proof.mjs` | snarkjs `fullProve` (timeout race, sama seperti live) + `verifyLocal`. VK dibaca dari JSON pre-export di `artifacts/` (fs serverless read-only, jadi tidak ada langkah CLI export saat cold start). |
| `src/witness.mjs` + `src/witness-config.gatekeeper.json` + `src/witness-config.steal.json` | Witness builder + config — salinan verbatim dari live. |
| `src/field.mjs`, `src/hmac.mjs`, `src/config.mjs`, `src/log.mjs` | Port ESM verbatim (semantik) dari live. Config: nama env + default sama persis dengan live untuk semua knob yang dipakai; knob Kurier/server dibuang. |
| `src/seen.mjs` | Seen-store pluggable (lihat §3). |
| `src/server.mjs` | Server lokal (127.0.0.1) yang membungkus transport core yang SAMA — untuk uji lokal tanpa `vercel dev`. |
| `artifacts/` | Salinan artefak circuit resmi + VK JSON: gatekeeper.wasm 1.755.820 B, gatekeeper_final.zkey 309.750 B, vfy-policy.wasm 2.991.212 B, vfy-policy_final.zkey 810.586 B, dua VK JSON ±5 KB. Total 5,7 MB. |
| `package.json` | `snarkjs` **0.7.6** (persis versi terpasang di agen live; sama dengan pin pecker), `js-sha3` 0.9.3, `@vercel/blob` 2.8.2, engines node 22.x (seperti pecker), `type: module`. |
| `vercel.json` | `functions.api/agent.mjs`: `maxDuration: 60`, `includeFiles: artifacts/**`; rewrites `/agent` → `/api/agent`, `/health` → `/api/agent` (persis pecker). |
| `.env.example`, `.gitignore` | Nama env saja, tanpa nilai. |
| `test/harness.mjs` | Harness uji lokal (lihat §4). |

## 2. Keputusan yang SENGAJA dipertahankan dari agen live (bukan dari pecker)

Perintah port: logika keputusan identik dengan live; hanya bentuk respons yang meniru pecker. Maka:

- **Urutan trap Gatekeeper = live:** VK_SUBSTITUTION → THRESHOLD_MISMATCH → PROOF_REUSED → EXPIRED → RECIPIENT_MISMATCH → AMOUNT_OVERFLOW. (Pecker menaruh PROOF_REUSED pertama — TIDAK ditiru.)
- **Semantik expiry = live:** reject bila `current_block > expiry_block` (pecker memakai `>=` — TIDAK ditiru).
- **Kode approve = live:** `VALID_CONDITION` (dari `APPROVE_REASON_CODE`; pecker memakai `VALID_PROOF` — TIDAK ditiru).
- **Tidak ada pengecualian retry-task-sama** di jalur keputusan (pecker punya; live tidak; dipertahankan live). Retry Steal tetap aman lewat cache jawaban (di bawah).
- **Format `STRATEGY_PARAMS` = live:** string JSON array `"[10,70,0,0,0,0,0,0]"` (pecker memakai format koma — TIDAK ditiru, agar nilai env live bisa disalin apa adanya). Params TIDAK diubah — strategi sama persis dengan yang jalan sekarang.
- **HMAC = live:** HMAC-SHA256 hex atas raw body + terima encoding alternatif (config switch yang sama).

## 3. Perubahan yang memang diminta port

- **Tanpa Kurier sama sekali.** Grep atas `src/` + `api/`: nol referensi Kurier di kode executable (kata itu hanya muncul di komentar/deskripsi paket yang menjelaskan ketiadaannya). Proof dibuat lokal, diverifikasi lokal, ditempel ke respons.
- **Steal: proof PINDAH ke dalam `policyProof`** = `{circuitVersion, publicInputsHash, proof, public_signals}` (bentuk pecker). Tidak ada lagi `proofReference`, tidak ada `proof`/`public_signals` level-atas pada respons Steal.
- **Idempotency Steal deterministik:** UUIDv5-shaped dari SHA-256(`matchId:turn`) — persis derivasi pecker — menggantikan `randomUUID()` per respons di live. Jawaban Steal yang sudah ber-proof di-cache per (mode, matchId, turn); retry platform menerima body **byte-identik** (terbukti di harness). Catatan: ini sengaja membatalkan satu ekspektasi suite live lama ("idempotencyKey unik per respons").
- **Seen-set pluggable** (`src/seen.mjs`), semantik dua set live (`accepted` + `all`, `SEEN_RULE` memilih):
  - `blob` — Vercel Blob, skema pathname pecker `seen/<set>/<proof_tx>/<taskId>`; dipilih otomatis bila `BLOB_READ_WRITE_TOKEN` ada. proof_tx di-lowercase untuk pathname (hash hex — satu-satunya deviasi sadar dari live yang memakai string mentah sebagai key).
  - `memory` — fallback tanpa token. **LIMITASI (didokumentasikan sesuai perintah):** reset tiap cold start dan per-instance — sesudah cold start, proof_tx yang pernah di-APPROVE instance sebelumnya bisa tampak fresh, jadi deteksi PROOF_REUSED terdegradasi menjadi "instance hangat ini saja". Cukup untuk practice/lokal; untuk ronde berskor, backend Blob WAJIB dikonfigurasi.
  - `file` — JSON lokal format identik live (hanya untuk dev/parity; tidak writable di Vercel).
  - Kegagalan Blob terdegradasi ke cache memori + log — filosofi sama seperti live ("store tak terbaca → deteksi terdegradasi", bukan crash).

## 4. Hasil uji lokal (WAJIB lulus sebelum laporan ini ditulis — lulus)

Harness: `node test/harness.mjs` — boot transport core port lewat `src/server.mjs` di port ephemeral dengan fixture `.env.test` milik agen live (secret/params/salt UJI — bukan `.env` live), plus satu panggilan langsung ke ekspor `POST`/`GET` milik `api/agent.mjs` (Request/Response Web-standard, persis cara Vercel memanggilnya). `npx vercel dev` tidak dicoba: ia butuh link project/login, yang dilarang tugas ini; harness memanggil fungsi ekspor yang sama sehingga jalur Vercel tetap terbukti.

**19/19 PASS dalam 9,7 dtk:**

| Kasus | Hasil | Latensi |
|---|---|---|
| health endpoint | PASS | — |
| preflight → `{ok:true, protocolVersion:"v1"}` + tanda tangan respons valid | PASS | 11 ms |
| HMAC salah → 401 | PASS | — |
| GK VALID_CONDITION → APPROVE + proof, 13 public signals, **verify lokal true**, shape pecker-exact | PASS | 1.385 ms (request pertama, termasuk warm-up wasm) |
| GK VK_SUBSTITUTION → REJECT + proof terverifikasi | PASS | 500 ms |
| GK THRESHOLD_MISMATCH → REJECT + proof terverifikasi | PASS | 637 ms |
| GK EXPIRED_CONDITION → REJECT + proof terverifikasi | PASS | 580 ms |
| GK RECIPIENT_MISMATCH → REJECT + proof terverifikasi | PASS | 651 ms |
| GK AMOUNT_OVERFLOW → REJECT + proof terverifikasi | PASS | 442 ms |
| GK PROOF_REUSED (setup approve → tx sama lagi) → REJECT **tanpa proof** | PASS | 3 ms |
| GK envelope rusak → fail-closed REJECT | PASS | 43 ms |
| Steal EXTRACT 10 → shape pecker, `publicInputsHash` == implementasi independen SPEC §5.4, proof di dalam `policyProof` (9 signals) **terverifikasi vs VK**, key deterministik, tanpa `proofReference`/proof level-atas | PASS | 916 ms |
| Steal retry → body **byte-identik** | PASS | 3 ms (cache) |
| Steal FORTIFY (self 50 < params[1] 70) → amount dihilangkan, proof terverifikasi | PASS | 1.119 ms |
| Steal HOLD (opp 0) → amount dihilangkan, proof terverifikasi | PASS | 959 ms |
| Steal envelope rusak → fail-closed HOLD | PASS | 4 ms |
| `api/agent.mjs` POST export → APPROVE + proof + signed | PASS | 622 ms |
| `api/agent.mjs` GET export → health | PASS | — |

Semua ekspektasi keputusan/kode di atas adalah ekspektasi yang sama dengan suite eval agen live (`agent/test/run-tests.js`) — paritas keputusan terhadap live terbukti pada matriks fixture yang sama, termasuk komitmen Poseidon(params, salt) yang dihitung harness dari fixture (bukan hardcode).

**Cold start (proses node baru, dua run):** import modul 379–768 ms; request GK pertama (compile wasm + prove + verify) 1.965–2.139 ms; total dingin 2,3–2,9 dtk; request hangat berikutnya 496–894 ms. Jauh di dalam deadline platform (GK 60 dtk, Steal ±30 dtk) dan `maxDuration` 60.

**Ukuran relevan bundle:** artefak 5,7 MB; `node_modules/snarkjs` 11 MB, `@vercel/blob` 1,7 MB (lokal `node_modules` total 109 MB termasuk devDependencies — BUKAN ukuran bundle; Vercel men-trace hanya dependensi yang diimpor. Verifikasi ukuran fungsi hasil trace adalah cek saat deploy pertama, belum terbukti di sini).

## 5. Perbandingan shape respons vs pecker (field-per-field)

Gatekeeper — pecker: `{decision, reason_code, proof_tx, proof, public_signals}`. Port: **identik** (urutan + nama field; harness meng-assert `Object.keys` persis). Beda isi yang disengaja: `reason_code` approve `VALID_CONDITION` (live) vs `VALID_PROOF` (pecker); kode trap pecker `PROOF_REPLAY` vs live/port `PROOF_REUSED`.

Steal — pecker: `{protocolVersion, matchId, turn, action, policyProof{circuitVersion, publicInputsHash, proof, public_signals}, agentTimestamp, idempotencyKey}`. Port: **identik** (kedua level di-assert persis di harness), termasuk `action.amount` hanya untuk EXTRACT dan derivasi idempotencyKey yang sama.

## 6. Langkah deploy yang tersisa (untuk agen utama, BELUM dilakukan)

1. Di akun Vercel Emanuel (jalanarsenal2-4292): buat/link project Vercel dari folder `vercel-port/` ini (root directory = folder ini bila di-push sebagai repo sendiri, atau jadikan repo GitHub baru — keputusan agen utama; JANGAN menimpa repo agen live).
2. Buat **Blob store (private)** di project itu → Vercel menerbitkan `BLOB_READ_WRITE_TOKEN`. Tanpa token ini seen-set jatuh ke mode memory (limitasinya di §3) — untuk ronde berskor, langkah ini wajib.
3. Set env var di project (NAMA di bawah; NILAI disalin dari env agen live yang sedang jalan — nilai tidak ditulis di laporan ini): `AGENT_GAMES_HMAC_SECRET`, `STRATEGY_SALT`, `STRATEGY_PARAMS` (format JSON live apa adanya), `BLOB_READ_WRITE_TOKEN` (dari langkah 2). Opsional bila live memakai non-default: `GATEKEEPER_SALT`, `SEEN_RULE`, `APPROVE_REASON_CODE`, `FALLBACK_REJECT_REASON_CODE`, `DECISION_APPROVE_VALUE`, `DECISION_REJECT_VALUE`, `HMAC_ALGO`, `HMAC_ENCODING`, `STEAL_PROOF_REQUIRED`.
4. Deploy, lalu cek: `GET /agent` → `{ok:true, configured:true, seenBackend:"blob"}`; perhatikan log ukuran fungsi hasil trace (cek batas ukuran Vercel).
5. **Preflight + practice dulu** dari dashboard (endpoint baru menunjuk `https://<project>.vercel.app/agent`): minimal 1 tugas Gatekeeper practice + 1 giliran Steal practice terverifikasi di platform — ini juga uji pertama apakah proof-dalam-respons kita dinilai platform (pertanyaan diagnostik terbuka dari evaluasi R03; port ini mereproduksi shape pecker, tetapi verifikasi platform atas public signals KITA hanya bisa dibuktikan di practice, bukan lokal).
6. **Pindah endpoint hanya antar-ronde, dengan jarak yang longgar** (perintah Emanuel 16 Nov: jangan mepet waktu berakhir ronde) dan pola make-before-break: endpoint Pinggy lama tetap hidup sampai endpoint Vercel lolos preflight + practice; sesudah pindah, pantau 1–2 tugas pertama ronde berikutnya sebelum keeper/tunnel lama dimatikan.

## 7. Blocker & batas kejujuran

- **Backend Blob belum teruji ke store sungguhan** (tidak ada token di lokal; `list`/`put` terverifikasi ada di @vercel/blob 2.8.2 terpasang, dan skema path meniru pecker yang produksi). Uji pertama = langkah deploy 2–4.
- **`vercel dev` tidak dijalankan** (butuh login/link) — digantikan harness yang memanggil ekspor fungsi yang sama persis.
- **Encoding witness diwarisi dari live apa adanya** — termasuk item yang di WITNESS-NOTES live masih berlabel asumsi terverifikasi-practice (mis. encoding taskId keccakModP). Port tidak menambah ketidakpastian baru, dan tidak menyelesaikan yang lama.
- **Verified proofs di platform tetap pertanyaan terbuka** (lihat checklist evaluasi R03): port ini meniru shape + penempatan proof pecker secara field-per-field dan semua proof lolos verifikasi lokal vs VK resmi, tetapi tarif +12 hanya bisa dikonfirmasi dari sesi practice/score sesudah deploy — TIDAK diklaim di sini.
- Node lokal uji v24.22.1; engines di-set 22.x seperti pecker (Vercel). snarkjs 0.7.6 berjalan di keduanya sejauh terbukti lokal (24) dan produksi pecker (22).
