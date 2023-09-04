import { ByteArray, Hex, isBytes, toHex } from "viem";
import { bufferToHex, publicToAddress } from "ethereumjs-util";
import { recoverPublicKey } from "./signature-utils";

export async function recoverAddress(msg: Buffer, signature: Hex | ByteArray): Promise<Hex> {
  let signatureHex = signature;

  if (isBytes(signature)) {
    signatureHex = toHex(signature);
  }

  const publicKey = recoverPublicKey(msg, signatureHex);
  const sender = publicToAddress(publicKey);
  return <Hex>bufferToHex(sender);
}
