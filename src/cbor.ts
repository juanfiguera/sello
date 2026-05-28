export type CborKey = number | string;

export type CborValue =
  | number
  | string
  | Uint8Array
  | readonly CborValue[]
  | CborTagged
  | CborMap;

export type CborMap = Map<CborKey, CborValue>;

export type CborTagged = {
  tag: number;
  value: CborValue;
};

export function cborTag(tag: number, value: CborValue): CborTagged {
  assertNonNegativeSafeInteger(tag, "tag");
  return { tag, value };
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (typeof value === "number") {
    return encodeInteger(value);
  }

  if (typeof value === "string") {
    return concat([encodeLength(3, utf8ByteLength(value)), encodeUtf8(value)]);
  }

  if (value instanceof Uint8Array) {
    return concat([encodeLength(2, value.byteLength), value]);
  }

  if (Array.isArray(value)) {
    return concat([
      encodeLength(4, value.length),
      ...value.map((entry) => encodeCbor(entry)),
    ]);
  }

  if (value instanceof Map) {
    return encodeMap(value);
  }

  if (isTagged(value)) {
    return concat([encodeLength(6, value.tag), encodeCbor(value.value)]);
  }

  throw new TypeError("unsupported CBOR value");
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new CborReader(bytes);
  const value = reader.readValue();
  reader.assertDone();
  return value;
}

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }

  return out;
}

function encodeInteger(value: number): Uint8Array {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError("CBOR integer must be a safe integer");
  }

  if (value >= 0) {
    return encodeLength(0, value);
  }

  return encodeLength(1, -1 - value);
}

function encodeMap(value: CborMap): Uint8Array {
  const entries = [...value.entries()].map(([key, entryValue]) => {
    if (typeof key !== "number" && typeof key !== "string") {
      throw new TypeError("CBOR map keys must be strings or numbers");
    }

    return {
      key: encodeCbor(key),
      value: encodeCbor(entryValue),
    };
  });

  entries.sort((a, b) => compareBytes(a.key, b.key));

  for (let index = 1; index < entries.length; index += 1) {
    if (compareBytes(entries[index - 1].key, entries[index].key) === 0) {
      throw new TypeError("CBOR map contains duplicate keys");
    }
  }

  return concat([
    encodeLength(5, entries.length),
    ...entries.flatMap((entry) => [entry.key, entry.value]),
  ]);
}

function encodeLength(majorType: number, value: number): Uint8Array {
  assertNonNegativeSafeInteger(value, "CBOR length/value");
  const prefix = majorType << 5;

  if (value < 24) {
    return Uint8Array.of(prefix | value);
  }

  if (value <= 0xff) {
    return Uint8Array.of(prefix | 24, value);
  }

  if (value <= 0xffff) {
    return Uint8Array.of(prefix | 25, value >> 8, value & 0xff);
  }

  if (value <= 0xffffffff) {
    return Uint8Array.of(
      prefix | 26,
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    );
  }

  throw new RangeError("CBOR values larger than uint32 are not supported yet");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.byteLength, b.byteLength);

  for (let index = 0; index < length; index += 1) {
    const diff = a[index] - b[index];
    if (diff !== 0) {
      return diff;
    }
  }

  return a.byteLength - b.byteLength;
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
}

function isTagged(value: unknown): value is CborTagged {
  return (
    typeof value === "object" &&
    value !== null &&
    "tag" in value &&
    "value" in value
  );
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function encodeUtf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function decodeUtf8(value: Uint8Array): string {
  return textDecoder.decode(value);
}

function utf8ByteLength(value: string): number {
  return encodeUtf8(value).byteLength;
}

class CborReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  readValue(): CborValue {
    const initialByte = this.readByte();
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    if (majorType === 0) {
      return this.readLength(additionalInfo);
    }

    if (majorType === 1) {
      return -1 - this.readLength(additionalInfo);
    }

    if (majorType === 2) {
      const length = this.readLength(additionalInfo);
      return this.readBytes(length);
    }

    if (majorType === 3) {
      const length = this.readLength(additionalInfo);
      return decodeUtf8(this.readBytes(length));
    }

    if (majorType === 4) {
      const length = this.readLength(additionalInfo);
      return this.readArray(length);
    }

    if (majorType === 5) {
      const length = this.readLength(additionalInfo);
      return this.readMap(length);
    }

    if (majorType === 6) {
      const tag = this.readLength(additionalInfo);
      return cborTag(tag, this.readValue());
    }

    throw new TypeError(`unsupported CBOR major type ${majorType}`);
  }

  assertDone(): void {
    if (this.#offset !== this.#bytes.byteLength) {
      throw new TypeError("CBOR data has trailing bytes");
    }
  }

  private readArray(length: number): CborValue[] {
    const out: CborValue[] = [];

    for (let index = 0; index < length; index += 1) {
      out.push(this.readValue());
    }

    return out;
  }

  private readMap(length: number): CborMap {
    const out: CborMap = new Map();
    let previousEncodedKey: Uint8Array | undefined;

    for (let index = 0; index < length; index += 1) {
      const keyStart = this.#offset;
      const key = this.readValue();
      const encodedKey = this.#bytes.subarray(keyStart, this.#offset);

      if (typeof key !== "string" && typeof key !== "number") {
        throw new TypeError("CBOR map keys must be strings or numbers");
      }

      if (previousEncodedKey && compareBytes(previousEncodedKey, encodedKey) >= 0) {
        throw new TypeError("CBOR map keys are not in deterministic order");
      }

      previousEncodedKey = encodedKey;
      out.set(key, this.readValue());
    }

    return out;
  }

  private readLength(additionalInfo: number): number {
    if (additionalInfo < 24) {
      return additionalInfo;
    }

    if (additionalInfo === 24) {
      const value = this.readByte();
      if (value < 24) {
        throw new TypeError("CBOR integer/length is not minimally encoded");
      }
      return value;
    }

    if (additionalInfo === 25) {
      const value = this.readUint16();
      if (value <= 0xff) {
        throw new TypeError("CBOR integer/length is not minimally encoded");
      }
      return value;
    }

    if (additionalInfo === 26) {
      const value = this.readUint32();
      if (value <= 0xffff) {
        throw new TypeError("CBOR integer/length is not minimally encoded");
      }
      return value;
    }

    throw new TypeError("CBOR indefinite or uint64 lengths are not supported");
  }

  private readByte(): number {
    if (this.#offset >= this.#bytes.byteLength) {
      throw new TypeError("unexpected end of CBOR data");
    }

    return this.#bytes[this.#offset++];
  }

  private readBytes(length: number): Uint8Array {
    const end = this.#offset + length;

    if (end > this.#bytes.byteLength) {
      throw new TypeError("unexpected end of CBOR data");
    }

    const out = this.#bytes.subarray(this.#offset, end);
    this.#offset = end;
    return out;
  }

  private readUint16(): number {
    return (this.readByte() << 8) | this.readByte();
  }

  private readUint32(): number {
    return (
      (this.readByte() * 0x1000000) +
      (this.readByte() << 16) +
      (this.readByte() << 8) +
      this.readByte()
    );
  }
}
