## 2025-02-19 - Skip Link & Focus Management
**Learning:** Adding a skip link and programmatic focus management is a low-effort, high-impact a11y win for SPAs.
**Action:** Always check for skip links in new projects and add them if missing. Ensure view transitions manage focus.

## 2025-05-20 - Icon-Only Buttons
**Learning:** Icon-only buttons (like 'close' actions) consistently lack accessible names, making them invisible to screen readers.
**Action:** Always verify icon-only interactive elements have `aria-label` or visually hidden text during initial audit.

## 2025-05-21 - Visual Feedback for Copy Actions
**Learning:** Users often miss toast notifications for quick actions like "copy to clipboard". Immediate visual feedback on the triggering element (e.g., icon swap, color change) significantly improves confidence and delight.
**Action:** Implement button state changes (icon/color) alongside toast notifications for copy actions to reinforce success.

## 2025-05-22 - Reusable Password Toggle Implementation
**Learning:** For SPAs using event delegation on the document body, generic UX components like a `.password-toggle` can be easily wired up to work universally without needing to attach individual event listeners to each element upon creation.
**Action:** When implementing micro-UX components in DOM-manipulation heavy SPAs, favor event delegation in the main script to ensure dynamically created instances (like modals) work automatically.
