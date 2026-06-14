import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { openHpkeBase, sealHpkeBase } from "../../src/hpke/base.ts";

describe("HPKE base mode", () => {
  it("matches RFC 9180 A.2.1 sequence 0 for X25519/HKDF-SHA256/ChaCha20-Poly1305", () => {
    const payload = sealHpkeBase({
      plaintext: hex("4265617574792069732074727574682c20747275746820626561757479"),
      aad: hex("436f756e742d30"),
      info: hex("4f6465206f6e2061204772656369616e2055726e"),
      recipientPublicKey: hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
      ephemeralPrivateKey: hex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"),
    });

    assert.equal(
      toHex(payload.subarray(0, 32)),
      "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    );
    assert.equal(
      toHex(payload.subarray(32)),
      "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    );

    const plaintext = openHpkeBase({
      payload,
      aad: hex("436f756e742d30"),
      info: hex("4f6465206f6e2061204772656369616e2055726e"),
      recipientPrivateKey: hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"),
    });

    assert.equal(
      toHex(plaintext),
      "4265617574792069732074727574682c20747275746820626561757479",
    );
  });

  it("rejects ciphertext opened with the wrong AAD", () => {
    const payload = sealHpkeBase({
      plaintext: new TextEncoder().encode("receipt"),
      aad: new TextEncoder().encode("aad"),
      info: new TextEncoder().encode("info"),
      recipientPublicKey: hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
      ephemeralPrivateKey: hex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"),
    });

    assert.throws(
      () =>
        openHpkeBase({
          payload,
          aad: new TextEncoder().encode("wrong"),
          info: new TextEncoder().encode("info"),
          recipientPrivateKey: hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"),
        }),
      /HPKE open failed/,
    );
  });
});

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
