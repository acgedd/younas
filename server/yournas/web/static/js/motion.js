// Motion helpers from the approved prototype. Every effect degrades to its end state when Motion is
// missing or the user asked for reduced motion.

import "../vendor/motion-12.23.12.js";

export const M = globalThis.Motion || {};
export const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

const NOOP = { stop() {}, pause() {}, play() {}, finished: Promise.resolve() };
const TRANSFORM_KEYS = ["x", "y", "rotate", "scale", "scaleX", "scaleY"];

export function tween(from, to, options = {}) {
  const { onUpdate, ...rest } = options;
  if (reduced || !M.animate) {
    if (onUpdate) onUpdate(to);
    return NOOP;
  }
  return M.animate(from, to, { ...rest, onUpdate });
}

// Motion would write individual transform properties; the prototype composes one transform string.
function toTransform(keyframes) {
  const keys = TRANSFORM_KEYS.filter((k) => k in keyframes);
  if (!keys.length) return keyframes;
  const out = { ...keyframes };
  for (const k of keys) delete out[k];
  const values = (k) => (Array.isArray(keyframes[k]) ? keyframes[k] : [keyframes[k]]);
  const length = Math.max(...keys.map((k) => values(k).length));
  const part = (k, v) => {
    if (k === "x") return `translateX(${v}px)`;
    if (k === "y") return `translateY(${v}px)`;
    if (k === "rotate") return `rotate(${v}deg)`;
    return `${k}(${v})`;
  };
  const frames = Array.from({ length }, (_, i) =>
    keys
      .map((k) => {
        const list = values(k);
        return part(k, list[Math.min(i, list.length - 1)]);
      })
      .join(" "),
  );
  out.transform = length === 1 ? frames[0] : frames;
  return out;
}

export function fx(el, keyframes, options = {}) {
  if (reduced || !M.animate || !el || el.length === 0) return NOOP;
  return M.animate(el, toTransform(keyframes), options);
}

export const stag = (seconds, options) => (M.stagger ? M.stagger(seconds, options) : 0);
export const done = (a) => (a && a.finished ? a.finished.catch(() => {}) : Promise.resolve());
export const canAnimate = () => Boolean(M.animate) && !reduced;
