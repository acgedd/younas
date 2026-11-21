// This device's own small database (IndexedDB): the Home cover settings and photos, and the ids of
// unfinished uploads so they can be found again after iOS kills the page. Nothing here leaves the
// device, and nothing here is a credential (the token stays in api.js).
//
// If IndexedDB is not available (private mode, Node in the tests), the same calls work against
// memory and the data simply does not survive a reload.

const DB_NAME = "yournas";
const DB_VERSION = 1;
const STORES = { kv: "key", uploads: "uploadId", covers: "id" };

const OPEN_TIMEOUT_MS = 3000;

const memory = { kv: new Map(), uploads: new Map(), covers: new Map() };
let opening = null;

function open() {
  if (opening) return opening;
  opening = new Promise((resolve) => {
    if (typeof indexedDB === "undefined") return resolve(null);
    let req;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      return resolve(null);
    }
    // Everything waits on this, so a hung open must not hold an upload or a sign-out; try again later.
    const giveUp = () => {
      clearTimeout(timer);
      opening = null;
      resolve(null);
    };
    const timer = setTimeout(giveUp, OPEN_TIMEOUT_MS);
    req.onupgradeneeded = () => {
      for (const [name, keyPath] of Object.entries(STORES)) {
        if (!req.result.objectStoreNames.contains(name)) req.result.createObjectStore(name, { keyPath });
      }
    };
    req.onsuccess = () => {
      clearTimeout(timer);
      const db = req.result;
      // The browser can close it under us (a suspended app): the next call opens a new one.
      db.onclose = () => {
        opening = null;
      };
      db.onversionchange = () => {
        db.close();
        opening = null;
      };
      resolve(db);
    };
    req.onerror = giveUp;
    req.onblocked = giveUp;
  });
  return opening;
}

function run(db, store, mode, work) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = work(tx.objectStore(store));
    tx.oncomplete = () => resolve(req.result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

async function use(store, mode, work, inMemory) {
  for (let attempt = 0; ; attempt += 1) {
    const db = await open();
    if (!db) return inMemory();
    try {
      return await run(db, store, mode, work);
    } catch (err) {
      // A connection closed without telling us: open a new one, once.
      if (attempt > 0 || !err || err.name !== "InvalidStateError") throw err;
      opening = null;
    }
  }
}

const put = (store, record) =>
  use(store, "readwrite", (s) => s.put(record), () => void memory[store].set(record[STORES[store]], record));
const get = (store, key) => use(store, "readonly", (s) => s.get(key), () => memory[store].get(key));
const del = (store, key) => use(store, "readwrite", (s) => s.delete(key), () => void memory[store].delete(key));
const all = (store) => use(store, "readonly", (s) => s.getAll(), () => [...memory[store].values()]);

// Settings. Keys that belong to one account carry its id, so another account on this device never
// reads them.
export async function kvGet(key, fallback = null) {
  try {
    const row = await get("kv", key);
    return row === undefined ? fallback : row.value;
  } catch {
    return fallback;
  }
}

export async function kvSet(key, value) {
  try {
    await put("kv", { key, value });
  } catch {
    /* a setting that cannot be saved only lasts until the next launch */
  }
}

// Unfinished uploads: { uploadId, user, space, dir, name, size, chunkMax, fingerprint, createdAt }.
export async function uploadsOf(user) {
  try {
    return (await all("uploads")).filter((u) => u.user === user);
  } catch {
    return [];
  }
}

export async function rememberUpload(record) {
  try {
    await put("uploads", record);
  } catch {
    /* the upload still runs; it just cannot be found again after a page kill */
  }
}

export async function forgetUpload(uploadId) {
  try {
    await del("uploads", uploadId);
  } catch {
    /* the server drops a stale upload by itself; a stale row answers 404 and is removed then */
  }
}

// Cover photos: { id, user, buf (ArrayBuffer, more reliable on iOS than a stored Blob), type }.
export async function coversOf(user) {
  try {
    return (await all("covers")).filter((c) => c.user === user);
  } catch {
    return [];
  }
}

export async function saveCover(record) {
  await put("covers", record);
}

export async function deleteCover(id) {
  try {
    await del("covers", id);
  } catch {
    /* it comes back on the next launch and can be removed again; sign-out clears it */
  }
}

// An explicit sign-out leaves nothing of this account on the device. Throws if that failed, so the
// caller can say so: unlike the calls above, a silent failure here would be a false promise.
export async function forgetUser(user) {
  const [covers, uploads] = await Promise.all([all("covers"), all("uploads")]);
  await Promise.all([
    ...covers.filter((c) => c.user === user).map((c) => del("covers", c.id)),
    ...uploads.filter((u) => u.user === user).map((u) => del("uploads", u.uploadId)),
    ...[`cover:${user}`, `dest:${user}`, `hint:${user}`, `awake:${user}`, `thumbjournal:${user}`].map((key) => del("kv", key)),
  ]);
}
