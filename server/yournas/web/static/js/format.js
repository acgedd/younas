// Formatting helpers: sizes, speeds, dates, file types.

export function bytes(n) {
  if (n == null) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i += 1;
  }
  const text = i === 0 || value >= 100 ? Math.round(value).toString() : value.toFixed(1);
  return `${text} ${units[i]}`;
}

export function rate(bytesPerSecond) {
  return (bytesPerSecond / 1e6).toFixed(1);
}

const pad = (n) => String(n).padStart(2, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// "Today 09:12", "Yesterday", "Oct 9" (this year) or "Oct 9, 2025".
export function when(iso, now = new Date()) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "-";
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diffDays = Math.round((day(now) - day(d)) / 86400000);
  if (diffDays === 0) return `Today ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (diffDays === 1) return "Yesterday";
  const md = `${MONTHS[d.getMonth()]} ${d.getDate()}`;
  return d.getFullYear() === now.getFullYear() ? md : `${md}, ${d.getFullYear()}`;
}

// The little badge in a file row: a folder has none of its own, a file shows its extension.
export function extOf(item) {
  if (item.kind === "dir") return "dir";
  const dot = item.name.lastIndexOf(".");
  if (dot <= 0 || dot === item.name.length - 1) return "file";
  return item.name.slice(dot + 1, dot + 5);
}
