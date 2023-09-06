import configs from "dotenv";
import {
  toBytes,
  hashMessage,
  ByteArray,
  toHex,
  serializeTransaction,
  PrepareTransactionRequestReturnType, keccak256, Hex, hexToBigInt, hashTypedData, TypedData,
} from "viem";
import { getPublicKey, getEthereumAddress, requestKmsSignature, determineCorrectV } from "./util/gcp-kms-utils";
import { joinSignature, splitSignature } from "./util/signature-utils";

configs.config();

export interface GcpKmsSignerCredentials {
  projectId: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  keyVersion: string;
}

export class GcpKmsSigner {
  readonly kmsCredentials: GcpKmsSignerCredentials;

  ethereumAddress: string;

  constructor(kmsCredentials: GcpKmsSignerCredentials) {
    this.kmsCredentials = kmsCredentials;
  }

  async getAddress(): Promise<string> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.kmsCredentials);
      this.ethereumAddress = getEthereumAddress(key);
    }
    return Promise.resolve(this.ethereumAddress);
  }

  async _signDigest(digestString: string): Promise<Hex> {
    const digestBuffer = Buffer.from(toBytes(digestString));
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials);
    const ethAddr = await this.getAddress();
    const res = await determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr);
    const v = hexToBigInt(toHex(res.v));

    return joinSignature({
      v,
      r: `0x${sig.r.toString("hex")}`,
      s: `0x${sig.s.toString("hex")}`,
    });
  }

  async signMessage(message: string | ByteArray): Promise<string> {
    return this._signDigest(
      hashMessage({
        raw: toHex(message),
      })
    );
  }

  /**
   * Original implementation takes into account the private key, but here we use the private
   * key from the GCP KMS, so we don't need to provide the PK as signature option.
   * Source code: https://github.com/MetaMask/eth-sig-util/blob/main/src/sign-typed-data.ts#L510
   * .
   * Sign typed data according to EIP-712. The signing differs based upon the `version`.
   *
   * V1 is based upon [an early version of EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
   * that lacked some later security improvements, and should generally be neglected in favor of
   * later versions.
   *
   * V3 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), except that arrays and
   * recursive data structures are not supported.
   *
   * V4 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), and includes full support of
   * arrays and recursive data structures.
   *
   * @param options.data - The typed data to sign.
   * @param options.version - The signing version to use.
   * @returns The '0x'-prefixed hex encoded signature.
   * @param data
   */
  async signTypedData(data: TypedData): Promise<string> {
    if (data === null || data === undefined) {
      throw new Error("Missing data parameter");
    }

    // @ts-ignore
    const typedHash = hashTypedData(data);
    return this._signDigest(typedHash);
  }

  async signTransaction(transaction: PrepareTransactionRequestReturnType): Promise<string> {
    const serializedTx = serializeTransaction(transaction);
    const transactionSignature = await this._signDigest(keccak256(toBytes(serializedTx)));
    return serializeTransaction(transaction, splitSignature(transactionSignature));
  }
}
