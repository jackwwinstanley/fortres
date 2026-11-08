# IBM Carbon Design System: a small accent for our data story

Goal: add a recognisable touch of Carbon to a custom dark page (Geist, flat greys
#181818 / #1F1F1F / #272727, mint/coral/lilac accents) without letting Carbon take over,
and be able to explain the choice to IBM judges.

How this was verified (2026-11-08): token values were read straight from the
published npm packages (`@carbon/motion@11.56.0`, `@carbon/layout@11.63.0`,
`@carbon/colors@11.62.0`, `@carbon/themes@11.85.0`, `@carbon/type@11.71.0`,
`@carbon/styles@1.119.0`, `@carbon/charts@1.27.27`, `@carbon/web-components@2.67.0`,
`@carbon/icons@11.92.0`) and from the Markdown sources of carbondesignsystem.com
(GitHub `carbon-design-system/carbon-website`, `src/pages/...`). Google Fonts URLs were
requested and returned HTTP 200. jsDelivr/unpkg could not be reached from the research
sandbox, so CDN URLs below are built from the package layout, not loaded in a browser.
Test them once on the real page.

Main sources
- https://carbondesignsystem.com (site) / https://github.com/carbon-design-system/carbon (code)
- Type: https://carbondesignsystem.com/elements/typography/overview/ and `@carbon/type`
- Colour: https://carbondesignsystem.com/elements/color/tokens/ and `@carbon/themes` (`scss/generated/_themes.scss`)
- Data viz: https://carbondesignsystem.com/data-visualization/color-palettes/ and `@carbon/charts` (`scss/_color-palette.scss`)
- Motion: https://carbondesignsystem.com/elements/motion/overview/ and `@carbon/motion`
- Grid / spacing: https://carbondesignsystem.com/elements/2x-grid/overview/ , https://carbondesignsystem.com/elements/spacing/overview/ and `@carbon/layout`

---

## 1. Type: IBM Plex and Carbon type tokens

Font stacks, from `@carbon/type`:
- Sans: `'IBM Plex Sans', system-ui, -apple-system, BlinkMacSystemFont, '.SFNSText-Regular', sans-serif`
- Mono: `'IBM Plex Mono', 'Menlo', 'DejaVu Sans Mono', 'Bitstream Vera Sans Mono', Courier, monospace`
- Also Plex Serif, Plex Sans Condensed, and script-specific Plex families (Arabic, Hebrew, JP, KR...).
- Carbon uses only three weights: light 300, regular 400, semibold 600.
- Type scale (px): 12, 14, 16, 18, 20, 24, 28, 32, 36, 42, 48, 54, ...

**Plex on Google Fonts: yes.** All of these returned 200:
```
https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&display=swap
https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;600&display=swap
```
(IBM Plex Serif, IBM Plex Sans Condensed, IBM Plex Sans Arabic also exist.) The npm
package `@ibm/plex` (6.4.1) is the official source, but Google Fonts fits our rules.

Productive vs expressive (typography overview page): the productive set is for product
UI, "where users need to complete tasks"; it uses fixed sizes and its tokens end in
`-01` style compact names. The expressive set has larger, fluid styles for editorial and
marketing moments, and its sizes step up at breakpoints.

Productive tokens (v11 names; size / weight / line-height / letter-spacing):

| Token | Size | Wt | LH | Tracking |
|---|---|---|---|---|
| `label-01` / `helper-text-01` / `legal-01` | 12px | 400 | 1.33333 | 0.32px |
| `code-01` (Plex Mono) | 12px | 400 | 1.33333 | 0.32px |
| `code-02` (Plex Mono) | 14px | 400 | 1.42857 | 0.32px |
| `body-compact-01` | 14px | 400 | 1.28572 | 0.16px |
| `body-01` | 14px | 400 | 1.42857 | 0.16px |
| `body-02` | 16px | 400 | 1.5 | 0 |
| `heading-compact-01` | 14px | 600 | 1.28572 | 0.16px |
| `heading-01` | 14px | 600 | 1.42857 | 0.16px |
| `heading-02` | 16px | 600 | 1.5 | 0 |
| `heading-03` | 20px | 400 | 1.4 | 0 |
| `heading-04` | 28px | 400 | 1.28572 | 0 |
| `heading-05` | 32px | 400 | 1.25 | 0 |
| `heading-06` | 42px | 300 | 1.199 | 0 |
| `heading-07` | 54px | 300 | 1.199 | 0 |

Expressive / fluid tokens (base size; they grow at larger breakpoints):
- `fluid-heading-03` 20px/400, `fluid-heading-04` 28px/400 (32px at larger breakpoints),
  `fluid-heading-05` 32px/400 (36px light and up), `fluid-heading-06` 32px/600.
- `fluid-paragraph-01` 24px/300, line-height 1.334 (28px at large).
- `fluid-display-01..04` start at 42px light, line-height 1.19; display-04 reaches 68px.

Signature Carbon look: big headlines in Plex Sans **Light 300**, small labels at 12px
with 0.32px tracking. For us, Plex Mono is the low-risk accent (numbers, IDs, code).

## 2. Colour: Gray 100 and Gray 90 themes and the IBM palette

Theme tokens (`@carbon/themes` 11.85.0, generated `_themes.scss`):

| Token | Gray 100 (g100) | Gray 90 (g90) |
|---|---|---|
| `background` | #161616 | #262626 |
| `layer-01` | #262626 | #393939 |
| `layer-02` | #393939 | #525252 |
| `layer-03` | #525252 | #6f6f6f |
| `layer-hover-01` | #333333 | #474747 |
| `field-01` | #262626 | #393939 |
| `border-subtle-00` | #393939 | #525252 |
| `border-subtle-01` | #525252 | #6f6f6f |
| `border-strong-01` | #6f6f6f | #8d8d8d |
| `border-interactive` | #4589ff | #4589ff |
| `text-primary` | #f4f4f4 | #f4f4f4 |
| `text-secondary` | #c6c6c6 | #c6c6c6 |
| `text-helper` | #a8a8a8 | #c6c6c6 |
| `text-placeholder` | rgba(244,244,244,0.4) | |
| `text-error` | #ff8389 | |
| `link-primary` | #78a9ff | #78a9ff |
| `interactive` | #4589ff | #4589ff |
| `focus` | #ffffff | #ffffff |
| `focus-inset` | #161616 | #161616 |
| `highlight` | #001d6c | |
| `support-error` | #fa4d56 | #ff8389 |
| `support-success` | #42be65 | #42be65 |
| `support-warning` | #f1c21b | #f1c21b |
| `support-info` | #4589ff | #4589ff |
| `support-caution-major` | #ff832b | |
| `overlay` | rgba(0,0,0,0.6) | |
| `button-primary` (component token) | #0f62fe | #0f62fe |

Note: Carbon g100 #161616 / #262626 / #393939 sits very close to our #181818 / #1F1F1F /
#272727. We do not need to change our greys; the match is already a talking point.

Dark-theme tag tokens (g90 = g100): green bg #0e6027, text #a7f0ba, border #24a148;
blue bg #0043ce, text #d0e2ff; red bg #a2191f, text #ffd7d9; purple bg #6929c4, text
#e8daff; teal bg #005d5d, text #9ef0f0. Notification background (success, error,
info, warning) is #262626 in g100 and #393939 in g90.

IBM palette steps (`@carbon/colors` 11.62.0), from 10 (lightest) to 100:

| Hue | 10 | 20 | 30 | 40 | 50 | 60 | 70 | 80 | 90 | 100 |
|---|---|---|---|---|---|---|---|---|---|---|
| blue | #edf5ff | #d0e2ff | #a6c8ff | #78a9ff | #4589ff | **#0f62fe** | #0043ce | #002d9c | #001d6c | #001141 |
| gray | #f4f4f4 | #e0e0e0 | #c6c6c6 | #a8a8a8 | #8d8d8d | #6f6f6f | #525252 | #393939 | #262626 | #161616 |
| green | #defbe6 | #a7f0ba | #6fdc8c | #42be65 | #24a148 | #198038 | #0e6027 | #044317 | #022d0d | #071908 |
| red | #fff1f1 | #ffd7d9 | #ffb3b8 | #ff8389 | #fa4d56 | #da1e28 | #a2191f | #750e13 | #520408 | #2d0709 |
| teal | #d9fbfb | #9ef0f0 | #3ddbd9 | #08bdba | #009d9a | #007d79 | #005d5d | #004144 | #022b30 | #081a1c |
| purple | #f6f2ff | #e8daff | #d4bbff | #be95ff | #a56eff | #8a3ffc | #6929c4 | #491d8b | #31135e | #1c0f30 |
| cyan | #e5f6ff | #bae6ff | #82cfff | #33b1ff | #1192e8 | #0072c3 | #00539a | #003a6d | #012749 | #061727 |
| magenta | #fff0f7 | #ffd6e8 | #ffafd2 | #ff7eb6 | #ee5396 | #d02670 | #9f1853 | #740937 | #510224 | #2a0a18 |
| yellow | #fcf4d6 | #fddc69 | #f1c21b | #d2a106 | #b28600 | #8e6a00 | #684e00 | #483700 | #302400 | #1c1500 |
| orange | #fff2e8 | #ffd9be | #ffb784 | #ff832b | #eb6200 | #ba4e00 | #8a3800 | #5e2900 | #3e1a00 | #231000 |

Blue 60 #0f62fe is "IBM blue": primary buttons and the brand colour.

## 3. Data visualisation guidance

Categorical palette, **dark themes**, 14 colours, in order (`@carbon/charts`
`$dark-theme-colors['14']`). The site says: "The colors of this palette should be applied
in sequence strictly as described below. The sequence is carefully curated to maximize
contrast between neighboring colors."

| # | Step | Hex |
|---|---|---|
| 1 | Purple 60 | #8a3ffc |
| 2 | Cyan 40 | #33b1ff |
| 3 | Teal 60 | #007d79 |
| 4 | Magenta 40 | #ff7eb6 |
| 5 | Red 50 | #fa4d56 |
| 6 | Red 10 | #fff1f1 |
| 7 | Green 30 | #6fdc8c |
| 8 | Blue 50 | #4589ff |
| 9 | Magenta 60 | #d02670 (older site docs show #d12771) |
| 10 | Yellow 40 | #d2a106 |
| 11 | Teal 40 | #08bdba |
| 12 | Cyan 20 | #bae6ff |
| 13 | Orange 60 | #ba4e00 |
| 14 | Purple 30 | #d4bbff |

There are also "grouped" palettes for a known number of categories (1 to 5 series);
for one series in dark themes Carbon Charts uses Purple 30 #d4bbff, the second option
Blue 50, then Cyan 40.

Sequential (monochromatic): "In dark themes, the lightest color denotes the largest
values." Dark mono-1 runs Purple 100 #1c0f30 up to Purple 10 #f6f2ff, then #ffffff;
mono-2 uses the same blue ramp, and there are cyan, teal and gray versions too.

Diverging: Palette 1 red-cyan ("hot vs cold": Red 80..10, white centre, Cyan 10..80);
Palette 2 purple-teal (for data with no temperature meaning, such as performance or
rates of change). The site says diverging palettes are the same for light and dark.

Alert palette: red = danger/error, orange = serious warning, yellow = warning,
green = normal/success.

Gradients: highlight extremes on single-category charts only; "Never use a gradient in
place of a sequential palette."

Chart rules (Axes and labels, Chart anatomy pages):
- Always start numeric axes at zero for bar/area and part-to-whole charts; line and
  scatter charts may crop the Y axis to show the direction of change.
- Never interpolate across gaps in data; label the start and end of the missing period.
- Axis breaks: draw a sinusoidal line in place of the straight axis line; 16px break on Y
  (16px minimum on X); during a break, line segments at 0.5px stroke, hide point circles.
- Time series: never change tick increments to fit data; set "landmark" labels (new
  day/month/year) in semibold.
- Titles should be descriptive and state the main insight; prefer direct labels on the
  chart to long legends; tooltips repeat both axis values.
- Donut/pie: callout labels for slices under 3 degrees; a "big number" (KPI) may sit in
  the donut centre, e.g. "15,250 browsers".

Fit with our page: Carbon's dark categorical order begins purple, cyan, teal, magenta,
which is close to our lilac and mint. We can use Carbon steps for a secondary chart or
for the alert colours without clashing.

## 4. Motion

Easing (`@carbon/motion` 11.56.0; same values in the motion overview tables):

| Curve | Productive | Expressive |
|---|---|---|
| standard | `cubic-bezier(0.2, 0, 0.38, 0.9)` | `cubic-bezier(0.4, 0.14, 0.3, 1)` |
| entrance | `cubic-bezier(0, 0, 0.38, 0.9)` | `cubic-bezier(0, 0, 0.3, 1)` |
| exit | `cubic-bezier(0.2, 0, 1, 0.9)` | `cubic-bezier(0.4, 0.14, 1, 1)` |

Productive motion is for efficient, responsive UI (tables, dropdowns, toggles).
Expressive motion is for "occasional, important moments" (page open, primary action,
key notification). "Productive motion is significantly faster than expressive motion."

Durations:

| Token | Value | Use (from source) |
|---|---|---|
| `duration-fast-01` | 70ms | button, toggle |
| `duration-fast-02` | 110ms | fade in/out of small elements |
| `duration-moderate-01` | 150ms | small expansion, short moves (default) |
| `duration-moderate-02` | 240ms | expansion, system communication, toast |
| `duration-slow-01` | 400ms | large expansion, important notifications |
| `duration-slow-02` | 700ms | background dimming, large hero transitions |

Rule of thumb: productive curve + fast/moderate for controls, expressive curve +
moderate-02/slow for the one or two big reveals.

## 5. 2x Grid and spacing

2x Grid (overview page): the basic unit is the **8px mini unit**; "divide or multiply by
two". Padding inside a grid box is 16px; "the margin around each grid box matches its
padding, for a total gutter of 32 pixels." Gutterless grids are allowed for closely
related content.

Breakpoints (`@carbon/layout`): sm 320px / 4 columns / 0 margin; md 672px / 8 cols / 16px;
lg 1056px / 16 cols / 16px; xlg 1312px / 16 cols / 16px; max 1584px / 16 cols / 24px.

Spacing scale:

| Token | rem | px |
|---|---|---|
| `$spacing-01` | 0.125rem | 2 |
| `$spacing-02` | 0.25rem | 4 |
| `$spacing-03` | 0.5rem | 8 |
| `$spacing-04` | 0.75rem | 12 |
| `$spacing-05` | 1rem | 16 |
| `$spacing-06` | 1.5rem | 24 |
| `$spacing-07` | 2rem | 32 |
| `$spacing-08` | 2.5rem | 40 |
| `$spacing-09` | 3rem | 48 |
| `$spacing-10` | 4rem | 64 |
| `$spacing-11` | 5rem | 80 |
| `$spacing-12` | 6rem | 96 |
| `$spacing-13` | 10rem | 160 |

Fluid spacing: `fluid-spacing-01..04` = 0, 2vw, 5vw, 10vw.

## 6. What reads as "IBM" at a glance, and plain-CSS versions

Signals:
- **Sharp corners.** v11 buttons, tiles, inputs and notifications have 0 radius (rounded
  corners only arrive behind the `enable-v12-release` flag). The one exception is the
  **pill tag** (16px radius).
- **Focus ring**: `outline: 2px solid $focus (#ffffff); outline-offset: -2px` (an inset
  white box), with a dotted style under `prefers-contrast`.
- **Inline notification, low contrast**: dark layer background, 3px left accent bar in the
  support colour, 1px border, 16px icon, bold title plus body text on one line.
- Tiles: flat `layer-01` rectangles with no shadow and 16px padding; Plex Light headings;
  12px labels with 0.32px tracking; Blue 60 primary buttons with the label on the left
  and the icon on the right.

Pill tag (Carbon green tag, md size 24px):
```css
.cds-tag{display:inline-flex;align-items:center;gap:4px;min-height:24px;
  padding:0 8px;border-radius:16px;font:400 12px/1.33333 'IBM Plex Sans',sans-serif;
  letter-spacing:.32px;background:#0e6027;color:#a7f0ba}
```

Inline notification, success (low contrast, g100):
```css
.cds-notif{display:flex;gap:12px;align-items:flex-start;max-width:608px;
  min-height:48px;padding:14px 16px 14px 13px;background:#262626;
  border:1px solid rgba(66,190,101,.3);border-left:3px solid #42be65;border-radius:0;
  color:#f4f4f4;font:400 14px/1.28572 'IBM Plex Sans',sans-serif;letter-spacing:.16px}
.cds-notif svg{flex:none;width:20px;height:20px;fill:#42be65}
.cds-notif strong{font-weight:600;margin-right:4px}
.cds-notif:focus-visible,.cds-tag:focus-visible{outline:2px solid #fff;outline-offset:-2px}
```
(The 3px bar, #262626 background and #42be65 colour come from `@carbon/styles`
`notification--experimental` and the g100 tokens; the border alpha is our own guess.)

**Carbon Web Components from a CDN.** The official prebuilt bundles are on IBM's own
CDN (from the package README), e.g.
`https://1.www.s81c.com/common/carbon/web-components/version/v2.65.0/dropdown.min.js`.
That host is **not** on our allowlist. The npm package (`@carbon/web-components@2.67.0`)
ships ES modules under `es/components/<name>/index.js`, but they import bare names
(`lit`, `@carbon/icons/es/...`), so a plain `<script type="module">` pointing at unpkg or
the raw jsDelivr file will fail without a build step. jsDelivr's ESM rewrite should handle
this:
```html
<script type="module"
  src="https://cdn.jsdelivr.net/npm/@carbon/web-components@2.67.0/es/components/tag/index.js/+esm"></script>
<cds-tag type="green">Granite Guardian: passed</cds-tag>
```
This has **not been tested** (jsDelivr was blocked in the research sandbox), it pulls in
Lit plus the component styles, and the package README warns that v3 changes how
components register. **Recommendation: use the plain CSS above** for one tag and one
notification. It weighs less, has nothing that can break, and looks the same.

## 7. Carbon icons without a build

`@carbon/icons@11.92.0` ships raw SVG files at `svg/16/`, `svg/20/`, `svg/24/`, `svg/32/`
(32 holds about 2,780 icons; the other sizes have only a few dozen), plus JS descriptor
objects under `es/<name>/16.js` (not ready-to-use SVG). Easiest path: fetch the SVG
file and inline it in the HTML (paths use `currentColor`-friendly fills, viewBox 0 0 32 32).
```
https://cdn.jsdelivr.net/npm/@carbon/icons@11.92.0/svg/32/checkmark--filled.svg
https://unpkg.com/@carbon/icons@11.92.0/svg/32/security.svg
```
Useful names that exist: `checkmark--filled`, `warning--alt`, `information`, `security`.
Copy the SVG markup in by hand rather than hot-linking, so the page has no runtime fetch.

## 8. Ideas for our page (small, accent-only)

1. **"Granite Guardian check passed" notification.** When the story shows a model output
   being screened, slide in one Carbon low-contrast success notification (3px #42be65
   bar, `checkmark--filled` icon, Plex Sans 14px) using `entrance-expressive`
   `cubic-bezier(0, 0, 0.3, 1)` over 240ms (`moderate-02`, the "toast" duration). It is the
   one place where "IBM" appears on purpose.
2. **Plex Mono for data.** Keep Geist for prose and headings; set numbers, record IDs,
   breach counts and code in IBM Plex Mono 400 (`code-02`: 14px, 0.32px tracking). It's
   one Google Fonts link, and every figure on the page gets a quiet IBM feel.
3. **Carbon pill tags as chart labels or filters.** Use green/purple/teal dark tag tokens
   (e.g. purple #6929c4 / #e8daff) for categories such as "PII", "credentials" or "flagged".
   Add the Carbon focus ring (2px white, -2px offset) to every interactive control.
4. **Carbon motion and palette on UI controls and one chart.** Toggles, tabs and tooltips
   use `standard-productive` `cubic-bezier(0.2, 0, 0.38, 0.9)` at 110 to 150ms, while scroll
   reveals stay custom. A secondary chart takes the first N colours of Carbon's dark
   categorical order (#8a3ffc, #33b1ff, #007d79, #ff7eb6...) and follows Carbon's
   "start bars at zero" and "never interpolate gaps" rules.

Line for the judges:
> "The story's look is our own, but anything that is *system feedback* (the Granite
> Guardian check, the tags, the focus states and the data type) is built on Carbon's
> Gray 100 tokens, Plex Mono and productive motion, so it would drop straight into an
> IBM product."
