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
    const response = await fetch(url, {
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

