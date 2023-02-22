import * as bitcoin from "bitcoinjs-lib";
import * as crypto from "crypto";
import randomBytes from "randombytes";
import { scrypt } from "scrypt-js";
import { v4 } from "uuid";
import ECPairFactory, { ECPairInterface } from "ecpair";
import * as ecc from "tiny-secp256k1";
const createHash = require("create-hash");
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const uuidv4 = v4;
// KDF

const enum KDFFunctions {
  PBKDF = "pbkdf2",
  Scrypt = "scrypt",
}

enum AddressType {
  P2PKH,
  SEGWIT,
  TAPROOT,
}

interface ScryptKDFParams {
  dklen: number;
  n: number;
  p: number;
  r: number;
  salt: Buffer;
}

interface ScryptKDFParamsOut {
  dklen: number;
  n: number;
  p: number;
  r: number;
  salt: string;
}

interface PBKDFParams {
  c: number;
  dklen: number;
  prf: string;
  salt: Buffer;
}

interface PBKDFParamsOut {
  c: number;
  dklen: number;
  prf: string;
  salt: string;
}

type KDFParams = ScryptKDFParams | PBKDFParams;
type KDFParamsOut = ScryptKDFParamsOut | PBKDFParamsOut;

// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
interface V3Keystore {
  crypto: {
    cipher: string;
    cipherparams: {
      iv: string;
    };
    ciphertext: string;
    kdf: string;
    kdfparams: KDFParamsOut;
    mac: string;
  };
  id: string;
  version: number;
}

function validateHexString(paramName: string, str: string, length?: number) {
  if (str.toLowerCase().startsWith("0x")) {
    str = str.slice(2);
  }
  if (!str && !length) {
    return str;
  }
  if ((length as number) % 2) {
    throw new Error(`Invalid length argument, must be an even number`);
  }
  if (typeof length === "number" && str.length !== length) {
    throw new Error(
      `Invalid ${paramName}, string must be ${length} hex characters`
    );
  }
  if (!/^([0-9a-f]{2})+$/i.test(str)) {
    const howMany =
      typeof length === "number"
        ? length
        : "empty or a non-zero even number of";
    throw new Error(
      `Invalid ${paramName}, string must be ${howMany} hex characters`
    );
  }
  return str;
}

function validateBuffer(paramName: string, buff: Buffer, length?: number) {
  if (!Buffer.isBuffer(buff)) {
    const howManyHex =
      typeof length === "number"
        ? `${length * 2}`
        : "empty or a non-zero even number of";
    const howManyBytes = typeof length === "number" ? ` (${length} bytes)` : "";
    throw new Error(
      `Invalid ${paramName}, must be a string (${howManyHex} hex characters) or buffer${howManyBytes}`
    );
  }
  if (typeof length === "number" && buff.length !== length) {
    throw new Error(`Invalid ${paramName}, buffer must be ${length} bytes`);
  }
  return buff;
}

function mergeToV3ParamsWithDefaults(
  params?: Partial<V3Params>
): V3ParamsStrict {
  const v3Defaults: V3ParamsStrict = {
    cipher: "aes-128-ctr",
    kdf: "scrypt",
    salt: randomBytes(32),
    iv: randomBytes(16),
    uuid: randomBytes(16),
    dklen: 32,
    c: 262144,
    n: 262144,
    r: 8,
    p: 1,
  };

  if (!params) {
    return v3Defaults;
  }

  if (typeof params.salt === "string") {
    params.salt = Buffer.from(validateHexString("salt", params.salt), "hex");
  }
  if (typeof params.iv === "string") {
    params.iv = Buffer.from(validateHexString("iv", params.iv, 32), "hex");
  }
  if (typeof params.uuid === "string") {
    params.uuid = Buffer.from(
      validateHexString("uuid", params.uuid, 32),
      "hex"
    );
  }

  if (params.salt) {
    validateBuffer("salt", params.salt);
  }
  if (params.iv) {
    validateBuffer("iv", params.iv, 16);
  }
  if (params.uuid) {
    validateBuffer("uuid", params.uuid, 16);
  }

  return {
    ...v3Defaults,
    ...(params as V3ParamsStrict),
  };
}

function kdfParamsForPBKDF(opts: V3ParamsStrict): PBKDFParams {
  return {
    dklen: opts.dklen,
    salt: opts.salt,
    c: opts.c,
    prf: "hmac-sha256",
  };
}

function kdfParamsForScrypt(opts: V3ParamsStrict): ScryptKDFParams {
  return {
    dklen: opts.dklen,
    salt: opts.salt,
    n: opts.n,
    r: opts.r,
    p: opts.p,
  };
}

interface V3Params {
  kdf: string;
  cipher: string;
  salt: string | Buffer;
  iv: string | Buffer;
  uuid: string | Buffer;
  dklen: number;
  c: number;
  n: number;
  r: number;
  p: number;
}

interface V3ParamsStrict {
  kdf: string;
  cipher: string;
  salt: Buffer;
  iv: Buffer;
  uuid: Buffer;
  dklen: number;
  c: number;
  n: number;
  r: number;
  p: number;
}

export class Wallet {
  private readonly keyPair: ECPairInterface;
  private privateKey: Buffer;
  private publicKey: Buffer;
  network: bitcoin.Network = bitcoin.networks.bitcoin;
  constructor(
    privateKey?: Buffer,
    publicKey?: Buffer,
    network?: bitcoin.Network
  ) {
    this.network = network;
    if (privateKey && publicKey) {
      throw new Error(
        "Cannot supply both a private and a public key to the constructor"
      );
    }

    if (privateKey) {
      this.keyPair = ECPair.fromPrivateKey(privateKey);
      this.privateKey = privateKey;
      this.publicKey = this.keyPair.publicKey;
    }

    if (publicKey) {
      this.publicKey = publicKey;
      this.keyPair = ECPair.fromPublicKey(publicKey);
    }
  }

  // static methods

  /**
   * Create an instance based on a new random key.
   *
   */
  public static generate(network?: bitcoin.Network): Wallet {
    const keyPair = ECPair.makeRandom({ network });
    return new Wallet(keyPair.privateKey);
  }

  /**
   * Create an instance where the address is valid against the supplied pattern (**this will be very slow**)
   */
  // public static generateVanityAddress(
  //   pattern: RegExp | string,
  //   network: bitcoin.Network
  // ): Wallet {
  //   if (!(pattern instanceof RegExp)) {
  //     pattern = new RegExp(pattern);
  //   }
  //   // todo
  // }

  /**
   * Create an instance based on a public key (certain methods will not be available)
   *
   * This method only accepts uncompressed Ethereum-style public keys, unless
   * the `nonStrict` flag is set to true.
   */
  public static fromPublicKey(publicKey: Buffer): Wallet {
    return new Wallet(undefined, publicKey);
  }

  /**
   * Create an instance based on a raw private key
   */
  public static fromPrivateKey(privateKey: Buffer): Wallet {
    return new Wallet(privateKey);
  }

  /**
   * Import a wallet (Version 3 of the Ethereum wallet format). Set `nonStrict` true to accept files with mixed-caps.
   *
   * @param input A JSON serialized string, or an object representing V3 Keystore.
   * @param password The keystore password.
   */
  public static async fromV3(
    input: string | V3Keystore,
    password: string
  ): Promise<Wallet> {
    const json: V3Keystore =
      typeof input === "object" ? input : JSON.parse(input);

    if (json.version !== 3) {
      throw new Error("Not a V3 wallet");
    }

    let derivedKey: Uint8Array, kdfparams: any;
    if (json.crypto.kdf === "scrypt") {
      kdfparams = json.crypto.kdfparams;

      // FIXME: support progress reporting callback
      derivedKey = await scrypt(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, "hex"),
        kdfparams.n,
        kdfparams.r,
        kdfparams.p,
        kdfparams.dklen
      );
    } else if (json.crypto.kdf === "pbkdf2") {
      kdfparams = json.crypto.kdfparams;

      if (kdfparams.prf !== "hmac-sha256") {
        throw new Error("Unsupported parameters to PBKDF2");
      }

      derivedKey = crypto.pbkdf2Sync(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, "hex"),
        kdfparams.c,
        kdfparams.dklen,
        "sha256"
      );
    } else {
      throw new Error("Unsupported key derivation scheme");
    }

    const ciphertext = Buffer.from(json.crypto.ciphertext, "hex");
    const mac = createHash("sha256")
      .update(
        Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), ciphertext])
      )
      .digest("hex");
    if (mac.toString("hex") !== json.crypto.mac) {
      throw new Error("Key derivation failed - possibly wrong passphrase");
    }

    const decipher = crypto.createDecipheriv(
      json.crypto.cipher,
      derivedKey.slice(0, 16),
      Buffer.from(json.crypto.cipherparams.iv, "hex")
    );
    const seed = runCipherBuffer(decipher, ciphertext);
    return new Wallet(seed);
  }

  // private getters

  /**
   * Returns the wallet's public key.
   */
  private get pubKey(): Buffer {
    return this.publicKey;
  }

  /**
   * Returns the wallet's private key.
   */
  private get privKey(): Buffer {
    if (!this.privateKey) {
      throw new Error("This is a public key only wallet");
    }
    return this.privateKey;
  }

  // public instance methods

  /**
   * Returns the wallet's private key.
   *
   */
  // tslint:disable-next-line
  public getPrivateKey(): Buffer {
    return this.privKey;
  }

  public getPrivateKeyString(): string {
    return this.privateKey.toString();
  }

  /**
   * Returns the wallet's public key.
   */
  // tslint:disable-next-line
  public getPublicKey(): Buffer {
    return this.pubKey;
  }

  /**
   * Returns the wallet's public key as a "0x" prefixed hex string
   */
  public getPublicKeyString(): string {
    return this.pubKey.toString();
  }

  /**
   * Returns the wallet's address.
   */
  public getAddress(
    type: AddressType = AddressType.P2PKH,
    network: bitcoin.Network = bitcoin.networks.bitcoin
  ): string {
    if (type === AddressType.P2PKH) {
      const { address } = bitcoin.payments.p2pkh({
        pubkey: this.publicKey,
        network: network,
      });
      return address;
    } else if (type === AddressType.SEGWIT) {
      const { address } = bitcoin.payments.p2wpkh({
        pubkey: this.publicKey,
        network: network,
      });
      return address;
    } else if (type === AddressType.TAPROOT) {
      const { address } = bitcoin.payments.p2tr({
        internalPubkey: this.publicKey.slice(1, 33),
        network: network,
      });
      return address;
    }
  }

  /**
   * Returns the wallet's address as a "0x" prefixed hex string
   */
  public getAddressString(
    type: AddressType = AddressType.P2PKH,
    network: bitcoin.Network = bitcoin.networks.bitcoin
  ): string {
    return this.getAddress(type, network);
  }

  /**
   * Returns an Etherem Version 3 Keystore Format object representing the wallet
   *
   * @param password The password used to encrypt the Keystore.
   * @param opts The options for the keystore. See [its spec](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition) for more info.
   */
  public async toV3(
    password: string,
    opts?: Partial<V3Params>
  ): Promise<V3Keystore> {
    if (!this.privateKey) {
      throw new Error("This is a public key only wallet");
    }

    const v3Params: V3ParamsStrict = mergeToV3ParamsWithDefaults(opts);

    let kdfParams: KDFParams;
    let derivedKey: Uint8Array;
    switch (v3Params.kdf) {
      case KDFFunctions.PBKDF:
        kdfParams = kdfParamsForPBKDF(v3Params);
        derivedKey = crypto.pbkdf2Sync(
          Buffer.from(password),
          kdfParams.salt,
          kdfParams.c,
          kdfParams.dklen,
          "sha256"
        );
        break;
      case KDFFunctions.Scrypt:
        kdfParams = kdfParamsForScrypt(v3Params);
        // FIXME: support progress reporting callback
        derivedKey = await scrypt(
          Buffer.from(password),
          kdfParams.salt,
          kdfParams.n,
          kdfParams.r,
          kdfParams.p,
          kdfParams.dklen
        );
        break;
      default:
        throw new Error("Unsupported kdf");
    }

    const cipher: crypto.Cipher = crypto.createCipheriv(
      v3Params.cipher,
      derivedKey.slice(0, 16),
      v3Params.iv
    );
    if (!cipher) {
      throw new Error("Unsupported cipher");
    }

    const ciphertext = runCipherBuffer(cipher, this.privKey);
    const mac = createHash("sha256")
      .update(
        Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), ciphertext])
      )
      .digest("hex");
    return {
      version: 3,
      id: uuidv4({ random: v3Params.uuid }),
      // @ts-ignore - the official V3 keystore spec omits the address key
      address: this.getAddress().toString("hex"),
      crypto: {
        ciphertext: ciphertext.toString("hex"),
        cipherparams: { iv: v3Params.iv.toString("hex") },
        cipher: v3Params.cipher,
        kdf: v3Params.kdf,
        kdfparams: {
          ...kdfParams,
          salt: kdfParams.salt.toString("hex"),
        },
        mac: mac.toString("hex"),
      },
    };
  }

  /**
   * Return the suggested filename for V3 keystores.
   */
  public getV3Filename(timestamp?: number): string {
    /*
     * We want a timestamp like 2016-03-15T17-11-33.007598288Z. Date formatting
     * is a pain in Javascript, everbody knows that. We could use moment.js,
     * but decide to do it manually in order to save space.
     *
     * toJSON() returns a pretty close version, so let's use it. It is not UTC though,
     * but does it really matter?
     *
     * Alternative manual way with padding and Date fields: http://stackoverflow.com/a/7244288/4964819
     *
     */
    const ts = timestamp ? new Date(timestamp) : new Date();
    return [
      "UTC--",
      ts.toJSON().replace(/:/g, "-"),
      "--",
      this.getAddressString(),
    ].join("");
  }

  public async toV3String(
    password: string,
    opts?: Partial<V3Params>
  ): Promise<string> {
    return JSON.stringify(await this.toV3(password, opts));
  }
}

function runCipherBuffer(
  cipher: crypto.Cipher | crypto.Decipher,
  data: Buffer
): Buffer {
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
