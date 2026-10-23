import type { Transition } from "motion/react";

/*
 * Springs, not fixed curves. `bounce` ≈ 1 − damping ratio, `visualDuration` ≈ response.
 * Default is critically damped (no overshoot); only momentum-carrying gestures bounce.
 */
export const spring = {
  /** move / reposition — damping 1.0, response 0.4 */
  move: { type: "spring", bounce: 0, visualDuration: 0.4 } as Transition,
  /** drawers & sheets — damping 0.8, response 0.3 */
  sheet: { type: "spring", bounce: 0.2, visualDuration: 0.3 } as Transition,
  /** small UI (thumbs, pills, knobs) */
  snappy: { type: "spring", bounce: 0, visualDuration: 0.22 } as Transition,
  /** list items appearing */
  item: { type: "spring", bounce: 0, visualDuration: 0.32 } as Transition,
};
