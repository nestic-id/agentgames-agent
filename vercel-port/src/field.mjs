// Field-element encoders for witness building. BN254 (bn128) scalar field.
// Ported verbatim from the live agent's src/field.js. Every encoder returns
// a decimal string (snarkjs input format). Which encoder each signal uses
// lives in the witness-config JSON files next to this module.
import sha3 from "js-sha3";

const { keccak256 } = sha3;

export const BN254_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

export function modP(x) {
  let r = BigInt(x) % BN254_PRIME;
  if (r < 0n) r += BN254_PRIME;
  return r;
}

function keccakFieldFromBytes(buf) {
  return modP(BigInt("0x" + keccak256(buf))).toString();
}

export const encoders = {
  // "1000" -> 1000 ; also accepts numbers
  decimal(v) {
    return modP(BigInt(v)).toString();
  },
  // "0x7d..." (any hex integer) -> value mod p
  hex(v) {
    return modP(BigInt(v)).toString();
  },
  // Hash-like identity value: 0x-hex or decimal -> value mod p.
  hashField(v) {
    return modP(BigInt(v)).toString();
  },
  // EVM address (fits in one field element) -> value mod p
  address(v) {
    return modP(BigInt(v)).toString();
  },
  // task_id: hex string -> int; pure digits -> int; anything else
  // ("gk_8d31_...") -> keccak256(utf8) mod p. (Same convention as live;
  // also pecker's default keccakModP for task_R03_… style ids.)
  taskId(v) {
    const s = String(v);
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return modP(BigInt(s)).toString();
    if (/^[0-9]+$/.test(s)) return modP(BigInt(s)).toString();
    return keccakFieldFromBytes(Buffer.from(s, "utf8"));
  },
  // matchId: UUID -> strip dashes -> 0x int (same convention as SPEC §5.4)
  matchId(v) {
    const s = String(v).replace(/-/g, "");
    return modP(BigInt("0x" + s)).toString();
  },
  // keccak256(utf8(value)) mod p
  keccakUtf8(v) {
    return keccakFieldFromBytes(Buffer.from(String(v), "utf8"));
  },
  // array of decimal-ish values -> array of field strings
  decimalArray(v) {
    if (!Array.isArray(v)) throw new Error("decimalArray encoder expects an array");
    return v.map((x) => modP(BigInt(x)).toString());
  },
};

export function encode(encoderName, value) {
  const fn = encoders[encoderName];
  if (!fn) throw new Error(`unknown encoder: ${encoderName}`);
  return fn(value);
}
