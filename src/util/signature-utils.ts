import {
  MessageTypes,
  SignTypedDataVersion,
  TypedDataV1,
  TypedMessage,
  typedSignatureHash,
  TypedDataUtils,
} from "@metamask/eth-sig-util";
import { bufferToHex, publicToAddress, fromRpcSig, ecrecover } from "ethereumjs-util";
import { toHex, concat, toBytes, ByteArray, Hex, hexToBigInt, isHex } from "viem";
import { Signature } from "viem/src/types/misc";

/**
 * Recover the public key from the given signature and message hash.
 *
 * @param messageHash - The hash of the signed message.
 * @param signature - The signature.
 * @returns The public key of the signer.
 */
export function recoverPublicKey(messageHash, signature) {
  const sigParams = fromRpcSig(signature);
  return ecrecover(messageHash, sigParams.v, sigParams.r, sigParams.s);
}

/**
 * Validate that the given value is a valid version string.
 *
 * @param version - The version value to validate.
 * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
 * allowed.
 */
export function validateVersion(version: SignTypedDataVersion, allowedVersions?: SignTypedDataVersion[]): void {
  if (!Object.keys(SignTypedDataVersion).includes(version)) {
    throw new Error(`Invalid version: '${version}'`);
  } else if (allowedVersions && !allowedVersions.includes(version)) {
    throw new Error(
      `SignTypedDataVersion not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(", ")}`
    );
  }
}

/**
 * Recover the address of the account that created the given EIP-712
 * signature. The version provided must match the version used to
 * create the signature.
 *
 * @param options - The signature recovery options.
 * @param options.data - The typed data that was signed.
 * @param options.signature - The '0x-prefixed hex encoded message signature.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex address of the signer.
 */
export function recoverTypedSignature<V extends SignTypedDataVersion, T extends MessageTypes>({
  data,
  signature,
  version,
}: {
  data: V extends "V1" ? TypedDataV1 : TypedMessage<T>;
  signature: string;
  version: V;
}): string {
  validateVersion(version);

  if (data === null || data === undefined) {
    throw new Error("Missing data parameter");
  } else if (signature === null || signature === undefined) {
    throw new Error("Missing signature parameter");
  }

  let messageHash: Buffer;
  if (version === SignTypedDataVersion.V1) {
    messageHash = Buffer.from(typedSignatureHash(data as TypedDataV1));
  } else {
    messageHash = TypedDataUtils.eip712Hash(
      data as TypedMessage<T>,
      version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
    );
  }

  const publicKey = recoverPublicKey(messageHash, signature);
  const sender = publicToAddress(publicKey);
  return bufferToHex(sender);
}

export function splitSignature(signature: ByteArray | Hex): Signature {
  let res = signature;

  if (isHex(signature)) {
    res = toBytes(signature);
  }

  const r = res.slice(0, 32);
  const s = res.slice(32, 64);
  const v = res[64];

  return {
    r: toHex(r),
    s: toHex(s),
    v: hexToBigInt(toHex(v)),
  };
}

export function joinSignature({r, s, v}: Signature) {
  const parsed = splitSignature(toHex(concat([toBytes(r), toBytes(s), toBytes(v)])));
  return toHex(toBytes(concat([
    parsed.r,
    parsed.s,
    toHex(parsed.v),
  ])));
}
