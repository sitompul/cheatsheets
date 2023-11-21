/**
 * ES17+ util function.
*/

// Nullable type.
export type Null<T> = T | null;

// Force to num.
export function num(input: any): number {
  try {
    const n = Number(input);
    return isNaN(n) ? 0 : n;
  } catch {
    return 0;
  }
}

// randomRange : inclusive random range.
export function randomRange(min: number, max: number): number {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1) + min);
}

// numerator/denominator chance.
// If numerator = 1 and denominator = 3, there will be 33.33% chance this will output true.
export function chance(numerator: number, denominator: number): boolean {
  if (denominator === 0) return false;
  const n = Math.abs(numerator);
  const d = Math.abs(denominator);
  if (d <= n) return true;
  const r = randomRange(1, d);
  return r > 0 && r <= n;
}

// Check if value is null or undefined.
export function isNil(i: any): boolean {
  return i == null;
}

// Check if value is nilString.
export function nilStr(i: any): boolean {
  return typeof i === "string" || isNil(i);
}

// Check if value is nilNumber.
export function nilNum(i: any): boolean {
  return typeof i === "number" || isNil(i);
}

// Send HTTP request using fetch.
export async function req<Response, Body = Record<string, unknown>>(
  method: "POST" | "GET" | "PUT" | "DELETE" | "PATCH",
  url: string,
  opt?: {
    qs?: Record<string, string>,
    headers?: Record<string, string>,
    body?: Body,
    signal?: AbortSignal,
  }
): Promise<[response: Null<Response>, error: string]> {
  try {
    let headersRequest: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (opt?.headers) {
      headersRequest = {
        ...headersRequest,
        ...opt.headers,
      };
    }
    let u = url;
    if (opt?.qs) {
      const p = new URLSearchParams(opt.qs);
      u = `${u}?${p.toString()}`;
    }

    const response = await fetch(u, {
      method,
      body: opt?.body && Object.keys(opt.body).length
        ? JSON.stringify(opt.body)
        : undefined,
      headers: headersRequest,
      credentials: "include",
      signal: opt?.signal,
    });
    const data = await response.json() as Response;
    return [data, ""];
  } catch (e) {
    const err = (e as Error);
    const name = err?.name || "";
    if (name === "AbortError") return [null, "request aborted"];

    const message: string = (e as Error)?.message || "";
    return [null, message];
  }
}

// Date.

// Check if input is a date.
export function isDate(i: any): boolean {
  const d = new Date(i);
  return !isNaN(d.getTime()) && d.toString() !== "Invalid Date";
}

// Convert date into valid input of datetime-local.
export function toDateTimeLocal(date: Date): string {
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, "0");
  const day = date.getDate().toString().padStart(2, "0");
  const hours = date.getHours().toString().padStart(2, "0");
  const minutes = date.getMinutes().toString().padStart(2, "0");

  const datetimeLocalString = `${year}-${month}-${day}T${hours}:${minutes}`;
  return datetimeLocalString;
}

export function getLocaleTZ(): [locale: string, tz: string] {
  const l = navigator.language || "id-ID";
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Jakarta";
  return [l, tz];
}

// Better date string on browser.
// Return "" if failed.
export function dateString(i: any): string {
  if (!isDate(i)) return "";

  const d = new Date(i);
  const [locale, timeZone] = getLocaleTZ();
  return new Intl.DateTimeFormat(locale, {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "2-digit",
    hour: "numeric",
    minute: "numeric",
    timeZone,
  }).format(d);
}

// Encryption algorithm that used in backend.
const algo: RsaHashedImportParams = {
  name: "RSA-OAEP",
  hash: {
    name: "SHA-256",
  },
};

// Encrypt using RSA private key.
export async function encryptRSA(publicKeyStr: string, plaintext: string): Promise<string> {
  const keyBuffer = new TextEncoder().encode(publicKeyStr);
  try {
    const publicKey = await window.crypto.subtle.importKey(
      "spki",
      keyBuffer,
      algo,
      false,
      ["encrypt"],
    );
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(plaintext);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      algo,
      publicKey,
      dataBuffer,
    );

    // Convert the ciphertext to a base64-encoded string
    const ciphertextBase64 = btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer)));
    return ciphertextBase64;
  } catch {
    return "";
  }
}

// WARNING: Decrypt RSA don't use this on browser, since you'll be exposing private key to your
// browser.
export async function decryptRSA(privateKeyStr: string, ciphertextBase64: string): Promise<string> {
  const keyBuffer = new TextEncoder().encode(privateKeyStr);
  try {
    const privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      algo,
      false,
      ["decrypt"],
    );

    const decoder = new TextDecoder();
    const ciphertextBuffer = new Uint8Array(
      atob(ciphertextBase64).split("").map(char => char.charCodeAt(0)),
    );

    const plaintextBuffer = await window.crypto.subtle.decrypt(
      algo,
      privateKey,
      ciphertextBuffer
    );

    const plainText = decoder.decode(plaintextBuffer);
    return plainText;
  } catch {
    return "";
  }
}
