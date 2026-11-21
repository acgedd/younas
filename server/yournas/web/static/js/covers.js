// Home cover photos the user picks from their own device. They stay on this device.
//
// The Content-Security-Policy allows same-origin images only (no blob:, no data:), so a photo is
// decoded with createImageBitmap and drawn on a <canvas>. Re-encoding through the canvas also drops
// the photo's metadata (location, camera) before it is stored.

const MAX_INPUT_BYTES = 40 * 1000 * 1000;
const MAX_SIDE = 1400;
export const MAX_COVERS = 8;

export function coverFit(width, height, maxSide) {
  const scale = Math.min(1, maxSide / Math.max(width, height));
  return { width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)) };
}

export function toBlob(canvas, quality) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("encode failed"))), "image/jpeg", quality);
  });
}

// File -> { buf, type }. Throws when the browser cannot decode the file.
export async function encodeCover(file) {
  if (file.size > MAX_INPUT_BYTES) throw new Error("too large");
  const bitmap = await createImageBitmap(file);
  try {
    const size = coverFit(bitmap.width, bitmap.height, MAX_SIDE);
    const canvas = document.createElement("canvas");
    canvas.width = size.width;
    canvas.height = size.height;
    canvas.getContext("2d").drawImage(bitmap, 0, 0, size.width, size.height);
    const blob = await toBlob(canvas, 0.82);
    return { buf: await blob.arrayBuffer(), type: blob.type };
  } finally {
    bitmap.close();
  }
}

export function decodeCover(record) {
  return createImageBitmap(new Blob([record.buf], { type: record.type }));
}

// Draw at no more than maxSide pixels; object-fit on the canvas crops it to its box.
export function paint(canvas, bitmap, maxSide = MAX_SIDE) {
  const size = coverFit(bitmap.width, bitmap.height, maxSide);
  canvas.width = size.width;
  canvas.height = size.height;
  canvas.getContext("2d").drawImage(bitmap, 0, 0, size.width, size.height);
}
