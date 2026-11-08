# taste-skill (leonxlnx/taste-skill 2.5.1): digest for "Before the Breach"

Source: https://github.com/leonxlnx/taste-skill, skill `design-taste-frontend` 2.5.1 (MIT). Read in full:
README, SKILL.md, all 21 files in `references/`, the effects README and index, motion meta, backgrounds
index, `layout/heroes.json`, `library/palettes.json`, `library/type.json`, moments index, component
metas. CHANGELOG skimmed for rule changes. Product photo and 3D print material skipped (it holds no
general rules beyond "never filter a photograph").

Paths below are relative to `skills/taste-skill/` in the clone at
`/tmp/claude-0/-home-user-ibm-breach/8d73b1e4-8833-50d3-b8df-97f61473209d/scratchpad/skills/taste-skill/`.

## 0. How to read this for our page

The skill builds company websites (cafes, SaaS, games). It sorts every brief into a "kind" and lets
only "tech" kinds (software, gaming, hardware) carry shaders, loops and scroll scenes. Our page is a
data story about security vulnerabilities for IBM: the nearest kind is **software/tech**, so the tech
budgets apply (one effect, one or two scroll moments, one count, four WebGL contexts at most). Its
sales machinery (main action, booking, prices, addresses, phone bar) mostly does not fit; those lines
are marked "Not applicable" below. Its strongest parts for us: the motion numbers, the "AI tells" for
copy and layout, the one section per screen discipline, the type and colour rules, the quality gate,
and a handful of reusable moments (`word-highlight`, `pinned-chapters`, `counter-rolls`).

The bar it sets: "looks made for this client, not from a template and not like an art piece".
Reference sites named throughout: figma.com and x.ai.

## 1. House rules (the nine that win over everything)

1. No caption or description under any image, render or visual. Credits go in one footer line.
   For us: no "Figure 1" or "Chart shows..." line under a chart. The heading above names it.
   (A chart's own axis labels, legend and annotations are part of the chart, not a caption.)
2. Every visual renders at 1440, 1024, 768 and 390: never an empty ground, blank canvas, or a
   reveal that never fired. A failed visual must show a still fallback.
3. One section per screen: the hero alone on the first screen, every section exactly one or two
   screens tall at 1440x900, no second section heading peeking in.
4. Equal left and right content edges.
5. Hover micro animations on everything clickable (numbers in section 6). No tilt, carousels or
   timed tabs. The hero enters once on load. Every page carries one dealt moment, two on a long page.
6. More and better real material; nicer backgrounds; better heroes, layouts and fonts.
7. Real full colour icons for real products (never a drawn look alike); small diagram visuals.
8. Effects, shaders and scenes only where the subject is technical (ours is).
9. Contacts: no house numbers, phones, register numbers. Not applicable (we have no address).

## 2. Kind and budgets that apply to us (tech column)

| Item | Tech budget |
|---|---|
| The one effect | one live ground (hero or one `[data-visual]` frame), or one WebGL part, or one big scene |
| Moments | 1 on a short page, 2 on a long page (8+ sections), in two different sections, never 3 |
| Beats (effect, scene, moments) | up to 3; never two in one section or neighbouring sections; a calm section between them; the back third of the page calm before the close |
| Timed loop | one per page, in the hero or the `[data-visual]` frame |
| Count (number rolling up) | once per page, never both `data-m-count` and `counter-rolls` |
| WebGL contexts live | 4 at most (hard cap); 24 made over the whole scroll fails |
| Pointer effect | one per page (hover light, liquid, magnetic: pick none or one) |
| Diagram cards | 0 to 2, pulsing |
| CSS grounds | 0 to 2 dealt, beyond the three ground tokens |

"The subject before the effect": an effect never stands where the real thing should be. For us the
real thing is the data (the fan chart, the bars, the table). An abstract shader in the hero instead
of a chart or a real number would read as filler (in their tests, pages that showed an effect in
place of the subject lost 3.5 to 5.5 points).

## 3. Page plan and section rules

### Plan in screens before building
Write one line per section: its id, its one idea, its picture, its height (1 or 2 screens), and which
section holds the effect or a moment and why it moves. "A motion with no purpose is cut." Example
purpose lines: "hero entrance: the name arrives first, then what to do"; "hover: every link answers".

### Section rules
- Every section shows the real thing (for us: a chart, the table, a real number set large). A section
  without a picture is allowed only for a price list, FAQ, specs table, form or a statement moment's
  own section, once each, and two picture free sections are never neighbours.
- The picture takes a real share: half a tile or more, 50/50 in a split, a whole screen as a layer.
- One idea per section, one h2.
- Merge short blocks: a quote, logo row, stat row or FAQ under 495px tall (464 at 390) goes into the
  section above as its last element, 64 to 96px under its content, with no heading of its own. An FAQ
  that reaches 495px with answers open is its own section.
- Repeats: a card layout (2x2, bento, three cards, split) at most twice a page; neighbours never share
  a layout; a calmer section (quote, table, FAQ) after at most two visual ones; the back third calm.
  Repeat the section scaffold (head, padding, ground logic) so it is learned once.
- Proof as small exact objects only: a footnoted figure, a named source. "No row of big stat numbers,
  no filler stat strips, no check icon lists, no logo wall."
- Two boxes deep at most (card > panel > content). Never a card in a card for text, never glass.
- At 768 and 820 (tablet held upright), plan the screens again: 832px of content per screen at 768x1024.

### The section box (exact)
- `main > section` and the footer: `height: calc(var(--h,1) * 100svh)`, `--h` 1 or 2. Under 640px
  use `100lvh` and `--hm`. Never `min-height` alone, never `dvh`, never a third screen, never a height
  set by script. (On phones a section may grow with content so nothing collides.)
- Padding: `--padt` 120 (96 on phone) above, the h2 sits there; `--padb` 72 (48) below.
- One screen at 1440x900 holds 708px of content (y 120 to 828).

| Content height at 1440x900 | Do |
|---|---|
| under 360 | merge into the section above, or add its picture |
| 360 to 495 | one screen, a warning: give it its picture |
| 495 to 708 | one screen |
| 708 to 1,320 | no height fits: cut to 708, split into two sections, or two groups (`.g2`) |
| 1,320 to 1,608 | two screens |
| over 1,608 | split |

- Top aligned: the h2 is the first content, never centre content vertically.
- Fill 0.55 or more of the box; a section over 35% empty warns, over 50% fails.
- Separation by a full width ground change or space only: no rules, shadows or hairlines between
  sections, no inset coloured box standing in for a ground.
- "The judge tile": every screenshot at scrollY = k x 900 shows exactly one section. Their study of
  327 sites: a section shows alone 80% of the time at 0.95 to 1.1 screens tall and gaps of 220px+.

Our caveat: a scroll driven story chapter (the fan chart walk) is a "moment" or "big scene", which is
allowed to be 2 screens live (photo chapters up to 4) with `position: sticky` inside its own box.

### The shell
`body` renders only the header, `main`, the closing footer. No popups, newsletter modals, chat
bubbles, back to top squares, badges, award strips. Nothing else is fixed or sticky.

## 4. Layout: edges, grid, splits

- One `.wrap` for header, every section and footer: `width: min(100% - 2 * var(--gut), 1280px)`,
  `--gut` 80 desktop / 24 phone (48 on tablet). Lines at x 80 and 1360 at 1440; x 24 and 366 at 390.
- 12 columns, 24px gutter (12 on phone). Column starts at 1440: 80, 189, 297, 406, 515, 623, 732, 841,
  949, 1058, 1167, 1275. Spans: 3 = 302, 4 = 410, 5 = 519, 6 = 628, 7 = 737. Phone: one 342 column
  or two 165 tiles 12 apart; nothing narrower than 165.
- Every block starts on the left line or a column start and ends on a column end. Anything wider than
  half the wrap runs the full wrap. Card rows: first card on the left line, last on the right, one
  height, every row full.
- Two text lines only: the left line and the page's split line (column 5, 6 or 7 start: x 623, 732 or
  841). Pick the split once and use it on every split, FAQ included.
- Centred text moves left: h1, section heads and the close all start on the left line. No centred or
  right aligned block wider than half the wrap. (The `centred` hero is the one exception.)
- Splits: text left, visual right, top aligned, on every split of the page. Never mirrored, never
  alternating. Phone: text first, then the visual, both 342 wide.
- Nothing crosses a section edge, is cut off, staggered or peeks out behind another. No sideways
  scroll at any width; no swipe rows; at 320 nothing past the screen.
- Bleed: full width only for layers behind a section's words. Never out to one side only.
- 1024 to 1279: span 4 cards with a panel go two up. 640 to 1023: splits stack text first, panel
  cards take the full row, no row half empty.
- Spacing scale (use only these): 4, 8, 12, 16, 24, 32, 48, 64, 96, 128 (`--s-1` to `--s-10`).
  Heading to content 48px (32 phone); cards 24px apart (12 phone).

## 5. The hero

- Exactly the first screen (`100svh`), the fixed header over its top; padding top 120 at 1440 (96
  phone), bottom 64 (24 phone). Content ends by y 836 at 1440x900. Nothing of the next section shows
  at 1440, 1280, 1024, 820, 768 and 390.
- Content: optional notice line, the h1, the sub line, at most two buttons, the picture.
  "One plain claim, never a slogan."
- h1 first, top at y 120, at most three lines at every width, never smaller than an h2 (28 to 60px
  on a phone). A notice line above it: one 14px line with a number, 16px above the h1.
- The hero has one quieter level of small text at most.
- The picture ends inside the hero. Never a first screen that ends on a visual cut by the fold, never
  1 to 95px of a box under the fold. At 768/820 it ends on a whole element (24px+ above the foot) or
  clearly bleeds (cut through 96px or more under a fade).
- Docked strip (software): one row under the hero content, at most 96px, still: e.g. three facts.
- Never a slider, crossfade, entry gate, loader, or an entrance that hides words.
- "Pictures in the hero are the work, never a colour field or a mood."

### Heroes that fit a data story (from `assets/layout/heroes.json`)
- `statement` ("Anthropic, Stripe Press, Mercury"): one calm sentence at 56px (34 phone), leading
  1.1, 2 lines (3 phone), max 54 chars, h1 max 21ch, lead max 42ch at 20/30 on 3 or 4 lines, 32px to
  buttons, then four facts on 4 x span-3 under a hairline docked at the hero's foot, 64px above the
  fold. Grounds it takes on tech: `horizon` (dark band with a lit rim), `deep`, `field`, `halo`,
  `dusk`, `grain`, `mist`, `liquid`; effects `aurora-curtains`, `grain-gradient`, `soft-light-bars`.
  Mistakes: a pale wash that reads as an empty page; a ground that fights the words; the statement
  centred; a second visual; a lead over three lines.
  Strong fit: "four facts docked under a hairline" = 72,670 ranked, 75 attacked, test years, result.
- `word` (x.ai, Vercel): h1 144px (54 phone), leading 0.92, 2 lines, max 28 chars, one live word
  last, underlined in the accent 0.05em thick; a new word every 2s for two rounds then rests; the
  slot as wide as the widest word so no line moves; four facts as a column on span-5 start-8 with
  hairline rows of 50. Mistakes: a slogan; more than four words in the rotation.
- `split`: text span-5, picture span-6 start-7, top aligned. h1 72/40, max 45 chars.
- `centred` (x.ai): pill, centred h1 72 (max 36 chars, 2 lines), lead, two pill buttons, then a lit
  frame across the wrap holding the product window, fading over its last 18%.
  For us: the window could be the fan chart's first frame.
- `editorial` is RETIRED (pictures inside a headline break a house rule).

Every hero: one screen, on the edge lines, one h1 within its `maxChars`, one motion of its own at
most, which rests under reduced motion and on a phone. Fails with a picture out to one viewport edge,
words over the busy part of a picture, a second float card, a slogan, a caption under the picture.

## 6. Motion (exact numbers; `references/motion.md`, `assets/motion/`)

### The rule: three layers of motion, nothing else moves
1. The hero's entrance on load, once (about 1.1s, then the hero stands).
2. One dealt moment in a section of its own (two on a long page), "big enough to remember".
3. The hover and press layer on every link, button, linked card.
On tech also: loops inside a card's visual, one timed loop in the hero or `[data-visual]`, one count.

**Scrolling moves nothing but the dealt moment.** No card, row or tile ever fades, rises or staggers
in as the page scrolls. No parallax on text. No scroll jacking, no smooth scroll library (Lenis,
Locomotive, ScrollSmoother banned). No scroll snap, no scroll tinted ground, no progress line, no
scroll spy marker, no count on view. A moment may hold its section with `position: sticky` while the
page scrolls natively. Content is readable at rest, without script and under reduced motion.

Our caveat: a data story is mostly scroll moments. Their rule translates to: every scroll driven
change lives inside a named story section (the fan chart, the rate bars), is scrubbed to the
scrollbar (runs back on the way up), shows a finished state at both ends, and everything else on the
page (table, FAQ, footer, prose) stays still.

### Tokens
| Token | Value | Use |
|---|---|---|
| `--m-in` | 150ms | hover in |
| `--m-out` | 120ms | hover out |
| `--m-press` | 90ms | press |
| `--m-panel` | 200ms | a menu opening |
| `--m-close` | 120ms | close |
| `--m-slide` | 240ms | an indicator travelling (tab pill) |
| `--m-image` / `--m-image-out` | 600ms / 400ms | photo zoom in / out |
| `--m-cycle` | 3.2s | card loop cycle (range 2.5 to 4s) |
| `--m-roll` | 700ms | digit roll (tech) |
| `--m-count` | 1000ms | count (1.2s at most) |
| `--m-level` | .6s | level bars |
| `--m-bob` | 3.2s | bob |

### Curves
- `--ease` (all UI steps): `cubic-bezier(.2,.8,.2,1)`.
- `--m-ease-enter` (an entrance settling: hero, moment, digit roll): `cubic-bezier(.22,1,.36,1)`.
- `--m-ease-io` (travel only): `cubic-bezier(.65,0,.35,1)`.
- Linear for loops and drifts.
- "No curve passes its mark: no bounce, no overshoot."
- Animate transform, scale and opacity only (hover may change colours). Never width, height, top,
  left, margin, padding, max-height. Inside a moment also clip-path, filter, text colour and (tech)
  background position, each named.

### Distances
Card lift 2px; photo zoom 1.02 to 1.03; arrow 3px; menu drop 6px; button step 1px up (2px on the XL
button); press 1px down and scale .985. No others.

### Hover layer
Only for a fine pointer: `(hover: hover) and (pointer: fine)`; keyboard focus shows the same state.
Nothing resizes or pushes a neighbour. No rotate, skew, glow, shine sweep or chip glide.

| Part | Motion | Time |
|---|---|---|
| Button | fill steps 14% toward the ink (outline gains a faint fill), box up 1px; press 1px below rest and scale .985 | 150 in / 120 out / 90 press |
| Arrow `svg.m-arrow` | 3px right and back; one arrow style per page | 150 / 120 |
| Link | rests on a faint 1px hairline; an ink line draws left to right, leaves to the right; nav and footer words rest bare, darken and draw a 1px line 4px under | 150 / 120 |
| Card with a link | lifts 2px, border darkens a step, optional soft shadow (blur 24px, 10% ink at most, hover only) | 180 in / 120 out |
| Card without a link | nothing | |
| Focus | 2px ring in the action colour, 2px off the control, no transition | none |
| Field | action border and a 3px soft ring | 140ms |
| Tabs (click only) | one indicator slides by transform; panel swaps 200ms at most; every panel one fixed height | 240ms |
| Copy button (tech) | glyph swaps to a check, holds 1.5 to 2s, returns | 150ms |

FAQ: every answer open, no accordion, nothing animates height.

### The hero entrance (exact)
- h1 rises line by line out of word masks: 700ms per line, lines 80ms apart, at most 240ms between
  first and last; each word starts wholly under its mask.
- Then lead, each button, the facts fade up 12px, 520ms each, 60ms apart, starting as the last line
  is half way up. A line above the h1 comes with its first line.
- The picture is never hidden and never fades: a photograph settles from 1.05 to 1 over 1.1s; a
  window, object or chart frame from .98 over 900ms, as one block.
- All about 1.1s, `--m-ease-enter`, transform/scale/opacity only, once a visit, never again on scroll.
- Head line so words wait without flashing (with a 700ms safety mark):
  `<script>document.documentElement.classList.add('m-enter');setTimeout(()=>document.documentElement.classList.add('m-enter-done'),700)</script>`
  and `data-enter` on the hero section. If script is later than the mark, words fade in over 400ms.
- Never a loader, a gate, a delay before reading, or a second entrance.

### Loops (tech)
- One cycle 2.5 to 4s (3.2 default), then repeat. Seeded on its finished picture; never an empty
  window; the last 10 to 15% of each cycle holds the finished picture; a reset dims and rewrites,
  never blanks. One change every 1 to 2s, each change 300ms or less.
- Pointer or focus entering the card restarts it (not in its first 800ms). Paused stays paused.
- Below the hero, two loops are never on one screen. Never two self moving things in one 900px window.
- Life signs only inside the looping visual: spinner 1s, live dot 2.4s (dot still, ring grows and
  fades), caret 1s. No typing dots, no lone pulsing dot elsewhere, no block cursor after a headline.
- A chart stays still (inside a card loop).

### Pause rule (WCAG 2.2.2)
Anything still moving 5s after it is seen has a round pause button: a solid 32px disc, 12px in from
the bottom right, same size and place everywhere, never over copy. Scroll driven moments need none.
Timed loops start on load and never start, stop or resume on scroll; an IntersectionObserver only
mounts lazily.

### Reduced motion, no script, phones
Colours still change; menus fade; a press shows as a deeper tone; indicators jump; the hero stands as
written; every loop, effect, moment shows its finished frame; numbers show final text; pause buttons
hidden. Phones: no hover states, heavy canvases become stills, but light moments still run (so a
phone page moves in two places too).

### Never (motion)
- A card, row or tile that reveals, staggers, slides or fades in on scroll; a fade in on every section.
- A section heading that rises on every section; an entrance longer than about 1.1s.
- A card that tilts, flips, follows the pointer or glows at the cursor; a magnetic button.
- A carousel, auto slider, timed tabs, rotating notice, logo marquee.
- Random blinking: twinkling dots, glitter, flicker, hue cycling, scrambled text. "Every change shows
  a state, a step or real data."
- A hover slower than its token, an overshooting ease, a delay before a button reacts, an animated
  focus ring, a second underline style.

## 7. Moments (the award site parts; `references/moments.md`, `assets/moments/`)

Rules: one per short page, two on 8+ sections, each id once, in different sections. A scroll moment
is scrubbed to the scrollbar inside its own section and shows a finished state at top and bottom
("every transition finishes before the section's top is a fifth of the screen down"). Text is live
and visible without the motion (opacity 1, 4.5:1 at every step). Reveals 600 to 1000ms ease out
`cubic-bezier(.22,1,.36,1)`; a scrubbed wipe takes about half of its chapter's share of the scroll and
holds for the rest. Never in a card. Still variant for phone and reduced motion is mandatory.

Moments worth using for us (all 0 WebGL, CSS variables plus a passive listener):

| id | What it does | Fit for us | Phone |
|---|---|---|---|
| `word-highlight` | one statement of 12 to 40 words rests at half ink (about 4:1) and turns to ink word by word as it crosses the middle of the screen; a `<strong>` word turns to the accent; runs back on scroll up; opts `from` 0.85, `to` 0.45 | The thesis line: "Of 72,670 known flaws, 75 were attacked..." | runs |
| `pinned-chapters` | a section holds for one screen of scroll while 2 to 4 steps open one at a time on the left and one frame on the right changes to each step (crossfade and settle); live section exactly two screens; needs 1024px+ wide and 640px+ tall | The method walk (data, model, ranking) or the fan chart's steps | static rows |
| `counter-rolls` | 2 to 4 proof figures roll once like an odometer when the row enters; strips start and end on the real digit so it never reads as zeros; duration 1400ms, stagger 90ms; right most digit turns most | The headline numbers (72,670 / 75) | figures stand |
| `letters-assemble` | a 2 to 5 word statement (up to about 28 letters) set very large; letters fly in from scattered, scrubbed, whole before mid screen | One short claim, e.g. "Before the breach" | stands |
| `line-carries-colour`, `iris-opens` | section transitions onto a new ground (line climbs, or a disc opens), inside an inset panel | the move into a dark results band | static |
| `marquee-row` | a row of real words moves sideways with a pause button | Not for us (reads as filler) | |

Retired by the skill (do not use): `headline-arrives` (a second entrance), `lines-rise` (repeats the
hero), `window-parallax` (parallax), `word-rotate`, `closing-lift` (words on a gradient).
`giant-type-pass` (photo inside letters) "reads as a template trick". `cursor-spotlight`,
`liquid-type`, `liquid-hover` are pointer effects: one per page at most; skip them for a projector.

Reuse: copy `assets/moments/moments.js`, `assets/moments/lib.js` and the moment folder
(`moment.js`, `moment.css`, `meta.json`). Head lines:
`<script>document.documentElement.classList.add('mo-js');setTimeout(()=>document.documentElement.classList.add('mo-safe'),2500)</script>`
plus `modulepreload` links, then `<script type="module" src="assets/moments/moments.js"></script>` at
the end of body. Host markup: `data-moment="<id>"`, options in `data-moment-opts`. The loader links
each moment's CSS; a failed module shows its finished state (`mo-safe`). Moments read page tokens
`--bg`, `--ink`, `--muted`, `--accent`, `--line` and the display face. No external dependency: plain
ES modules, works without a build step. Markup examples are in each `moment.js` header comment.
Model page: `assets/moments/_demo/in-page-service.html` (pinned-chapters in a real page).

## 8. Effects (`references/effects-usage.md`, `effects-creative.md`, `assets/effects/`)

### Rules
- One effect per page. Quiet grounds (even fields that hold UI): `grain-gradient`,
  `painterly-landscape`, `gradient-mesh`, `silk-folds`, `fluted-glass`. Focal grounds (have a
  subject; alone in the hero, nothing over them): `orb-sphere`, `spotlight-cone`, `god-rays`,
  `aurora-curtains`, `caustics`.
- Never in a fixed layer, never behind body copy, never a page long canvas.
- Text over an effect only on its quiet part at 4.5:1. Set `calmX`/`calmY` (0 to 1) where text sits.
- Effect behaviour: reacts to pointer or time; after assembling it holds, no constant churn; ambient
  cycles 4s or longer, drift a few px a second, 2 to 10% of pixels changing in 0.9s; poster first and
  a still fallback under reduced motion, on phones and when WebGL fails. Never sound.
- Cost: draw 20 to 25px larger than its box and clip; 1 sample per CSS px (0.75 when large), about
  1.5 megapixels, pixel ratio 1.5 at most; noise and particles at half resolution and 30fps or less.
- Still effects render once into a picture and free their context (`still()` in `components/shared.js`).
- Blend modes only inside the effect, never on text. "No glass or frosted look on any kind."
- Never violet or lavender. Never a print, dither or grade over a photograph.
- Retired as "bad or cheap": `riso-print`, `ink-bloom`, `liquid-chrome`, `metaballs`,
  `brushed-metal`, `paper-texture`, `terrazzo-speckle`, `marble-warp`, `pixel-mosaic`,
  `truchet-arcs`, `soft-particles` (stock bokeh). `grid-pulse` stays out of charts ("its traces blink
  at random"). `ridgeline` "reads as a record cover" alone.

### Effects that could suit a security data story
All in `assets/effects/<id>/effect.js`, each imports only `../fx.js` (no CDN, no build step; ES
modules, need http, not `file://`). Mount: `<div data-fx="<id>" data-fx-seed="21"
data-fx-params='{"speed":0}'></div>` then `import fx from './assets/effects/fx.js';
fx.mountAll(document);` (or `fx.mount(el, id, {palette, seed, params})` returning `pause`, `resume`,
`set`, `destroy`). Palette from CSS vars `--bg`, `--surface`, `--ink`, `--muted`, `--accent`,
`--accent-ink` (or `--fx-*`). Built in: pauses off screen and in hidden tabs, one still frame under
reduced motion, CSS fallback without WebGL, DPR capped at 1.75.

| id | Look (from index) | Note for us |
|---|---|---|
| `grain-gradient` | soft shapes drift under fine film grain | safest quiet hero or band ground; set `grainMotion` 0 for still |
| `contour-lines` | topographic map: thin contours, accent index lines, faint hillshade, breathing | a "terrain of risk" ground for a band; pattern, so never behind UI or the chart |
| `dot-terrain` | rolling land as a cloud of points like a laser scan | a statement band; pattern |
| `ascii-shade` | a turning sphere made of monospace characters, reads as code | on theme for security; focal, hero only |
| `halftone-screen` / `bayer-dither` | gradient or sphere as halftone dots / ordered dither pixels | still grounds only; never in a chart area |
| `soft-light-bars` | 4 to 7 soft upright bars of light to one side beside a gap for text | allowed on the `statement` hero |
| `aurora-curtains` | curtains of light over a night sky | dark statement hero; also fills digits (`fx-stat`) |
| `film-light-leak` | light bleeds in from one edge, blown core, moving grain | dark or colour only |
| `ruled-grounds` | fine dot ruling with a small cross every fourth node | allowed under chart areas (`fx-chart`) |

`gallery.html` and `lab.html` in `assets/effects/` preview all of them (serve over http).

### Creative components (`assets/components/<id>/`: `component.html`, `.css`, `.js`, `meta.json`)
Need `assets/system.css`, `components/base.css`, the part's css, and `components/shared.js` (which
imports `effects/fx.js`). `const part = init(root)`.

- `fx-chart` (area chart): one metric over 14 days, crisp accent line over a soft accent fade, its own
  grid, pointer and arrow key reading with a tooltip pinned inside the plot, a polite live region and
  a hidden table. Rules: real numbers; axis labels on the data's own scale; the fill stays inside the
  area and is still; one grid only; one live chart per screen. Good accessibility pattern to copy.
- `fx-bars`: bars start at zero on a labelled scale; mark the latest bar with a thin ring, "never by
  veiling the others"; no glass, satin or metal streaks; no motion inside bars; hidden table for
  values. Bars can be windows onto one still, low contrast `grain-gradient` (a printed material look).
  For our rate bars: the ring idea for the highlighted bar, the zero baseline, the hidden table.
- `fx-stat`: 2 to 4 proof numbers, 56px and up, weight 600, effect inside the digits (still), on dark
  or colour grounds only; on light, digits fade from ink to about 60% ink ("an effect inside digits
  on white reads as scratched metal"). "No count up on scroll: the final number shows at once." A note
  under the row says where the figures come from. Rendered as a `<dl>`.
- `fx-headline`: fill 2 to 3 words of the hero or closing line with the effect. Never body text, never
  two filled lines on a page.
- `fx-globe`, `fx-map`, `fx-pricing`, `fx-prompt`, `fx-avatar`, `fx-logos`, `fx-band`: Not applicable.

## 9. Diagrams (`assets/diagrams/`)

`diagram.js` (91 KB, no deps) + `diagram.css` + `mount.js` draw node and line visuals from JSON;
`presets.json` holds 27 specs; `lab.html` builds one live. Markup:
`<div class="dg" data-diagram="lanes-agent"></div>` + `<script type="module" src="assets/diagrams/mount.js">`.
Layouts: `hub`, `ring`, `tree`, `lanes` (one input, a core, parallel lanes), `fanin`/`bowtie`
(many into one), `sync`, `timeline`, `grid` (files into a pipeline), `free`.
Possible use: "72,670 CVEs in, model, ranked list out" as a `fanin` or `lanes` card.
Rules: one diagram a section, two a page; labels plain (a step by its result: "Ranked", not
"Orchestration layer"); up to 8 spokes, 12 nodes ("crowded means it should be a list"); pulse is a
gradient comet, one cycle 2.5 to 4s with a 0.24 to 0.5s stagger, restarts on pointer enter, still on
phone and reduced motion; accent only on the light and what it reaches; lines are hairlines; no
caption under it; `alt` in the spec. Icons must be fetched locally (`scripts/icons.mjs`); no CDN.

## 10. Backgrounds and colour (`references/backgrounds.md`, `system.md` Colour)

### Ground tokens (every kind)
- `--g-main`: white or a tint of lightness 0.80 to 0.97, low saturation (channel spread 0.12 or less);
  covers 55% or more of page height (60% on software). Cool grey or blue leaning for software.
- `--g-alt`: same hue within 20 degrees, 0.06 to 0.15 darker, never under 0.70 (e.g. `#ffffff` to
  `#f2f2ef`). Panels, tiles, at most one full band.
- `--g-dark`: lightness 0.05 or less: near black `#111` to `#1a1a1a` or the deepest brand shade, never
  charcoal, never violet. One dark body section at most, at the middle or later, never right under the
  hero; the footer may be dark. A fully dark page or dark hero is allowed on tech.
- Grounds change in big blocks at the section edge; no border or rule between sections.

### Colour rules
- The interface stays 90 to 95% neutral; colour comes from the content (for us, the data marks).
- One near black ink, often warm, never `#000`, for text, hairlines (12 to 15% of it), borders.
- One accent at most: the primary button, focus ring, links, state in visuals; under 3% of a screen
  elsewhere; its label 4.5:1 on it and it 3:1 on the ground.
- Highlight by contrast, never by colour: no marker highlights or coloured bars behind words; colour
  inside a word once a page at most.
- Never violet or lavender: any token with OKLCH hue about 270 to 330 is turned to 255 (blue) or 345
  (rose).
- No scrim or gradient over a photograph.
- The grade (light or dark) is chosen once on load or by a click, never by scrolling.

### Tech CSS grounds (`assets/backgrounds/backgrounds.css` + `backgrounds.js`, no WebGL)
16 grounds, one class on a section (`<section class="section bg-halo">`):
- Soft: `mist` (colour wash), `halo` (light behind a heading; `--halo-x`, `--halo-y`), `ruled` (fine
  grid on the container edges, clear behind the heading), `dots` (dots in the margins), `arcs` (rings
  rising, for the close, x.ai's footer), `liquid` (two slow blobs, the only moving one, needs pause).
- Hard: `grain`, `dusk` (one tone melting into the next), `band`, `field` (Figma's sand tile),
  `photo`, `horizon` (dark band with a lit rim like a planet's: "a statement the page is sure of
  (security, scale, a promise)"), `deep` (near black with a cool pool at the top, a lit lip and
  grain, x.ai's).
- Page level: `paper` on body, `topglow` around nav and hero.
- At most two dealt grounds a page, each once, never two strong ones as neighbours. A ground with
  grain, dither, texture or motion counts as the page's one effect.
- Ink keeps 7:1 and muted 4.5:1 on every ground.
- `horizon` and `deep` are the two most on brief for "Before the Breach".

### Code drawn ground recipes (if we hand write our own)
Mix in OKLCH, ground chroma under 0.12. Build light first: a radial with 4 to 6 stops in one hue, then
grain 4 to 10%; every dark gradient gets a static dither. Never a two stop linear gradient as
decoration (linear only as an edge fade inside a visual). Grain: one tile made at load, never animated,
never over UI, text or photographs.
- Corner glow (dark footer, closing band): a radial near one corner, radius 110 to 130%, five eased
  stops so no ring shows.
- Spotlight floor (dark hero): a light pool 70% wide, a blurred shadow, side vignettes.
- Painterly field: 4 to 6 large ellipses in the tones, blurred 60 to 120px, drawn 10% oversize.
- Grid marks (dots or plus signs at column crossings, 12 to 18% ink) only on one dark technical band,
  a data panel or the footer, never over text. A hairline ledger is 1px sibling rules at 12 to 15% ink.

### Palettes that fit (from `library/palettes.json`, 64 palettes)
- `white-link-blue` "Sheet and biro": bg `#ffffff`, surface `#f4f4f4`, ink `#111111`, muted
  `#6b6b6b`, accent `#1a4be0`; footer may invert to `#111111`. Only links and the one button are blue.
- `cool-grey-cobalt`: bg `#eef0f3`, surface `#e2e5ea`, ink `#0b0c0e`, muted `#5d6470`, accent
  `#1f2de6`, field `#1f2de6`/white.
- `cool-white-slate` "Frost and slate": bg `#f7f9fa`, surface `#ecf0f2`, ink `#1f3038`, muted
  `#5d6b72`, accent `#0d7480` (teal, once).
- `blue-black-cornflower` "Night and sky blue": bg `#0a0d14`, surface `#131824`, ink `#e9edf3`, muted
  `#8891a1`, accent `#5ab9fc`, accentInk `#0a0d14`. No section changes colour.
- `graphite-safety-orange`: bg `#18191b`, surface `#222427`, ink `#eff0f1`, muted `#9c9ea3`, accent
  `#ff4a1f`, field `#eff0f1`/`#18191b`: graphite and light grey sections alternate. A warning orange
  reads as "breach".
- `black-crimson`: bg `#0a0a0a`, surface `#151515`, ink `#efefef`, muted `#8c8c8c`, accent `#b11226`.
- `soot-pale-lime`: bg `#0f0f0f`, surface `#1a1a1a`, ink `#ffffff`, muted `#8f8f8f`, accent `#dafa9c`.
Projector note (ours): dark pages wash out on many projectors; a light page with a dark band for
results, or a mid graphite, is safer. Keep ink at 7:1.

## 11. Type (`references/layout-v4.md` section 5, `system.md` Type, `library/type.json`)

- One family, or a display face plus a text face with fixed jobs; never three; at most four font
  files; Google Fonts with `display=swap`.
- Banned faces: Inter, Roboto, Open Sans, Lato, Montserrat, Poppins, Space Grotesk, Plus Jakarta Sans,
  the system look.
- Weights: headlines at the display weight (500 on tech, 400 on other); size and tight tracking carry
  them, "never bold and big". Text 400 and 500 only. Never 700 or 800. No light weight under 20px.
- Tracking: -0.5% to -4.5% at 40px and up (pairings give e.g. -0.035em, XL -0.045em).
- Sizes 1440/390: h1 72/38, h2 48/30, h3 and quotes 28/24, lead and card titles 20/18, body 16/26,
  small 14, labels 13/500 sentence case, stat 38/28 (`--t-stat`, under the h2). Each level at least
  1.3x the next from 1024 (1.2x below). Nothing under 13px. Lines at most 62 characters (`.measure`).
- Text people read is 16px or more, line height 1.5 to 1.8, ink at 7:1 or more. Muted (4.5:1) only for
  labels, dates, meta and a heading's grey run on. "Never 14px paragraphs or 15px grey card text."
- A figure never outgrows the h2 or h1, at 390 too. Display text of 40px+ counts as a heading.
- Sentence case everywhere; labels never tracked capitals or small caps; italic only for quotes and
  attributions; curly quotes; a number never breaks from its unit; every word live text, never baked
  into a picture; text never shrinks to fit.
- The grey run on heading: `<h2>Send invoices in minutes. <span class="muted">Clients pay by
  card.</span></h2>`: the first part ends with a full stop; never two phrases that run into one.
- `hyphens: auto` for words of 10 letters or more (the skill's default). Ours: turn this off; the user
  dislikes hyphens in copy, and broken words on a projector read badly.

Pairings that fit (exact families from `type.json`):
- `plex`: IBM Plex Sans (display 500, tracking -0.025, XL -0.035) + IBM Plex Mono. "Developer tools,
  security, data infrastructure: engineered and sober." On brand for IBM, but obvious.
- `geist`: Geist + Geist Mono, tracking -0.035/-0.045. "Exact, plain and fast."
- `chivo`: Chivo + Chivo Mono, display 400. "Grotesk with a matching mono" for data tools.
- `mona`: Mona Sans (wdth 75 to 125, stretch 104%) + Geist Mono; has a width axis for a `word` hero.
- `newsreader` (Newsreader + Hanken Grotesk) or `source-serif` (Source Serif 4 + Libre Franklin):
  a Guardian like serif headline over a sober sans, for an editorial data story.
A mono only for numbers, CVE ids and the table; tabular figures for every column of numbers.

## 12. Cards, panels, tables, FAQ (`references/cards.md`, `sections-library.md`)

- The card is barely there: one step off the page, 1px border at 8 to 14% ink, generous padding; the
  colour is inside the panel. No blurred shadow at rest. Radius `--r-lg` (20 on `soft`); padding 32
  from 1024, 28 below, 24 on phone, never under 24. Title one line at 20/18, weight 500; 8px; at most
  two lines at 16/24 in 84% ink, at most 46ch; 32px to the panel.
- Radius families on `<html data-radius>`: `sharp` 4/6/8 (fintech, developer tools; fits us),
  `soft` 8/12/20, `round` 10/16/24. Nested radius = outer minus margin (20 - 8 = 12), never under 6.
- Panels: the lower 60 to 65% of the card (`--p-h` 264 to 340px). Content cut by the panel's edge
  reads as "a glimpse of something bigger". Every edge keeps 24px of ground or is cut by 24px or more
  (never a 1 to 23px sliver), cut under a 64px fade that never covers the point.
- The accent appears once per fragment (the row being worked on, the last bar). Everything else ink
  tints. "Never a row of green dots."
- Tables (`comparison-table`): rows of `.grid` with `role=table`; 48px rows each closed by a 1px rule;
  group headings in 13px labels; "Nothing sticky"; on phone each option as its own block, never
  sideways scroll. Lists close each row with a 1px rule inside the content edges.
  For our top 500 table: no sticky header by their rule (we may judge otherwise for 500 rows), no
  sideways scroll on phone (stack the row as a block), tabular figures, 1px row rules.
- FAQ: the split, h2 "Questions" with a grey line on the left; 5 to 8 items on the right, question in
  `h3`, answer under it, each closed by a 1px rule; answers open on load, no accordion. Questions in
  the reader's words, at most 60 characters; answers under 50 words, starting with the answer.
  "Questions the company wants asked; answers that dodge" are the mistakes. Admit limits here.
- Steps: only with three real steps; no arrows or lines between cards; no huge display numerals.
- Timeline rail: four dated moments on one line, 1px line, 8px still dot, newest in the accent; never a
  pulsing dot. (Possible for "test years".)
- `quote-stat`: one number at `--t-stat` (38) beside a claim, a grey line of up to eight words; a stat
  that is a slogan is the mistake; no count up.

## 13. Copy rules (`copy.md`, `copy-voice.md`, `copy-moves.md`, `copy-registers.md`, `copy-tells.md`)

### Core
- "Say what it is and what it does, in words a stranger understands in five seconds." Every sentence
  one you would say out loud. No metaphors, poetry, invented terms or ad wording (one brand line per
  page at most, never the h1, with a fact in the line under it).
- The h1 names the subject in 2 to 8 words (for a site: the category and the buyer). Never a riddle,
  a command, a mood, or a brand line over a plain sub line.
- The first screen holds one hard fact: a number, a place, a price or a date. (Ours: 72,670 / 75.)
- Every heading has a noun that names a thing, 1 to 6 words, at most two lines. Never a bare command,
  a question (FAQ entries aside), a colon heading, or "a line that only makes sense after the page".
- Buttons: a verb plus what you get, 1 to 5 words. Never "Learn more", "Read more", "Discover",
  "Explore", "More", "Click here". (Ours: "See the top 500", "Read the method".)
- Under a heading: one line to two sentences (10 to 40 words). Card body 1 or 2 sentences, 25 words
  at most. No paragraph over five lines at 1440.
- Tech word budget: 60 to 80 words a screen at 1440 outside charts and UI; over 80 warns (117 read as
  wordy). Cut order: a second sentence under a heading, card bodies to one sentence of 12 to 18
  words, a fourth card, a list a visual already shows. Page about 900 words at most, footer aside.
- Numbers sit in sentences with their unit, uneven where real (212, 38%). A claim that needs a
  source gets a numbered footnote near the footer (13px and up).
- Each fact once: one value and one wording, repeated word for word only where it belongs.
- Nothing invented: no invented quotes, statistics, customers, awards. No "sample", "illustrative",
  asterisk notes, square brackets, lorem ipsum, TODO, `#` links.
- The page never talks about itself: no "This section shows", "Below, you'll find", "Here are 3
  reasons", "We've added".
- Self check: read each line aloud. Rival test: put another team's name in the h1 and each heading;
  a line that still reads true says nothing.

### Reader's questions decide the shape
What is this, is it for me, why believe you, how does it work, what does it cost, what if it goes
wrong, what do I do now. "A section exists only if there is true material for it. Five full sections
beat eight padded ones." "Not the skeleton: eyebrow, claim heading, two line lede, three cards,
figures, in every section." Vary: a list, a table, a short letter, one longer paragraph.
For non technical judges: they "do not know they have the problem", so open on a moment they
recognise, then the mechanism in verb led steps ("The model reads... It ranks... It flags...").

### Register (voice) to pick
`2. Technical and dry, with proof`: "a label paired with a hard figure; the mechanism in verb led
steps; real UI strings and file names on the page; the enemy is a category; jargon translated once;
the product as the subject." Fails when it turns into a spec dump with no pain named.
Alternative `9. Plain spoken activist`: a mission in one measurable sentence; the hard subject said
plainly; proof in numbers.
Avoid `0. The model's default`: warm, wry, modest, a little literary, deadpan twist endings,
"honest, calm, quiet, actually". Voice card format (write on the plan, never the page):
```
Voice: technical-dry (copy-registers.md 2)
Pairs: exact, not cold; sure, not loud; dry only in the empty state
Person: "you" for what the reader gets, "we" for the work
Sentences: mostly 8 to 16 words; one long one a section, where it explains
Humour: none in the hero, the results or the FAQ
House words: the data's own nouns (CVE, exploit, rank), the same word every time
Never: virtue words about ourselves, a pun on the name, a strip of claims
```

### Moves worth stealing
- Hero forms that work: "Category and a true, unexpected promise"; "A narrow superlative the data
  proves, and the next line says how".
- Section heading default: "the name with a claim under it" ("Rooms and prices" / "Six rooms, all
  with the lake on one side"). Or "a figure from the data" ("212 routes, reset every Tuesday").
- "Odd human numbers beat round big ones." "Every number sits in a sentence, beside the claim it
  proves." "Rhythm on purpose, once: a run of short sentences, one long sentence beside a short one."
- FAQ: "Admit limits in the FAQ"; "Ask the reader's real objection and answer it flatly".
- The close restates the hero's promise with one fact.
- Microcopy carries the voice: empty states, the table's "no results" line, error lines.

### Device budget per page (copy-lint counts; over = WARN, twice the budget plus one = FAIL)
| Device | Budget |
|---|---|
| Heading in two fragments "X. Y." | 1 |
| Number pair heading "Four X, one Y" | 0 to 1 |
| Negation run "No X. No Y." | 1 |
| Contrast "X, not Y", isn't, rather than, instead of, without the | 2 in all (count them together) |
| Dry closing line on a paragraph | 2, never in a row |
| Pun on the name | 1, never the h1 |
| Sign off line in the footer | 0 |
| Strip of figures | real figures only |
| Virtue words about ourselves | 0 |
| Lists of three | only when there are three things; never in consecutive sentences |
| Step numbers on cards | only where order is the content |
| Eyebrow labels | 1 or 2 a page |
| Em dashes | 2 in the body (WARN above) |

### AI tells: banned words and lines (copy-lint FAILs these)
- Slop words: delve, tapestry, testament to, realm, embark, beacon, multifaceted, paradigm, myriad,
  plethora, meticulous, intricate, interplay, garner, boasts; elevate, unlock, unleash, empower,
  harness, supercharge, turbocharge, seamless, effortless, cutting-edge, revolutionary,
  transformative, holistic, next-level, next-generation, world-class, best-in-class, game-changer,
  game-changing, state-of-the-art, bespoke, synergy, leverage, reimagine, powerful, robust, nestled,
  unparalleled, unrivalled. (Each stands in for a fact: "robust" for the failure case, "powerful" for
  the figure.)
- Stock lines: "In today's fast-paced world", "Unlock the power of", "The future of X is here", "Say
  goodbye to", "Whether you're A or B", "Join thousands of", "Trusted by teams worldwide", "Imagine a
  world where", "Ready to transform your X?", "Look no further", "one-stop shop", "X made simple", "at
  your fingertips", "in just a few clicks", "It's not just a X, it's a Y", "Not only X but also Y",
  "Here's the thing", "Let that sink in".
- Residue: "Certainly!", "I hope this helps", "[Company Name]", lorem ipsum, `{{tokens}}`, markdown
  `**` or `##` on the rendered page.
- Shapes (WARN): the ing rider (", ensuring a smooth start"); the question answered at once ("The
  result? Three hours back."); the colon reveal ("One thing changed: X"); "serves as", "stands as",
  "plays a key role".
- Dead metaphors: landscape, ecosystem, journey, "in the X space", hub, "the world of", "where X
  meets Y", "in the heart of". (Careful: "threat landscape" is exactly this tell.)
- Virtue words: honest, calm, quiet, actually, genuinely, truly, simply, thoughtful, carefully,
  intentional, steady, dependable.
- Second generation tells: invented specifics; the strip of three or four figures each over a one
  word label under the hero (fix: each number in the sentence it proves, or only real figures);
  polished testimonials; default cast names (Priya, Okafor, Marcus, Dana, Aisha, Maya, Theo, Elara...)
  and companies (Fieldnote, Kestrel, Halcyon, Acme, Northwind, Lumen, Nimbus, Apex, Zenith, Vertex);
  "perfect evenness" (every card the same length); proof figures ("3x faster", "10,000+ teams", "98%
  satisfied"); a stale copyright year; exclamation marks; all caps labels; emoji bullets; an arrow
  after every link.
- Over correction to watch: no em dashes breeds comma splices; no "not X but Y" breeds "rather than";
  no hype breeds calm vocabulary; avoiding threes breeds pairs everywhere; "be specific" breeds
  invented numbers; short sentences breed a drumbeat of fragments.
- Not tells (leave alone): perfect grammar, plain "is" and "has", "in order to", a list of three when
  there are three things, a refrain repeated on purpose, a narrow superlative the data proves.

### Older v2 bans worth keeping (from CHANGELOG, "AI tells" section 9)
Section numbering eyebrows (`00 / INDEX`, `06 · how it works`); version labels in the hero (`BETA`);
decorative text strips at the hero bottom (`BRAND. MOTION. SPATIAL.`); pills or labels laid over
images; version footers (`v1.4.2`); city, time or weather strips; scroll cues ("Scroll", "Scroll to
explore", a down arrow); `border-t` + `border-b` on every row of long lists; scoring or progress bars
with filled background tracks as comparison visuals; div built fake dashboards; floating top right
sub text in section headings; across 8 sections at least 4 different layout families; a bento with N
items has exactly N cells.
Note: v2 also said "use a hyphen instead of an em dash"; for this user, restructure the sentence.

## 14. System: nav, buttons, head, access, forms

- Header: `position: fixed`, full width, 72px (56 phone), opaque ground, a 1px hairline under it from
  the first paint, `z-index: 10`, the same at every scroll depth: "no blur, transparency, shrink,
  hide, shadow, colour flip or floating pill". Logo on the left line, main button on the right line.
  Four to six plain one word nouns at 15px/500 that never wrap, each with its own anchor. Current
  section: `aria-current` on one word, a 2px bar under it. (Note: the skill bans scroll spy markers;
  if we want chapter tracking, it is a deliberate break.)
- Buttons: 44px high, label 16px, 24px side padding, at most two in a row, full width on phone.
  Exactly one filled button per view; one secondary style; text links use one link style. Never a
  slanted, gradient, ghost or shadowed button, or a third style. One arrow style a page.
- Tap targets 44px outside running text; a target under 32px tall with another under 8px away fails.
- Access: every control named; `alt` on pictures, `role="img"` + `aria-label` on a drawn chart;
  headings step down one level at a time; no `tabindex` above 0; skip link first (`<a
  class="skip-link" href="#top">Skip to content</a>`); focus ring 2px in the action colour, 3:1, never
  animated, never under the fixed header; `lang` set.
- Head: `<title>` "Name: what it is", one sentence `meta description` (never the same words), `og:*`
  and `twitter:card summary_large_image` with a still of the hero as `share.jpg`, an svg favicon,
  `theme-color` = page ground. Viewport `width=device-width, initial-scale=1, viewport-fit=cover`.
  Reset: `*{box-sizing:border-box}`, `html,body{margin:0}`.
- `html { scroll-padding-top: 0; scroll-behavior: auto }` so anchor jumps land on a tile.
- Forms, booking, newsletter, contacts, maps, phone bar: Not applicable.

## 15. Performance budget (`references/perf.md`)

| Check | WARN | FAIL |
|---|---|---|
| Transfer (text gzipped) | > 1500 KiB | > 3000 KiB |
| Images total / largest | > 1200 / 350 KiB | > 2400 / 700 KiB |
| JS parsed / CSS | > 450 / 120 KiB | > 900 / 250 KiB |
| Requests | > 60 | > 110 |
| Font families / files / bytes | > 2 / 4 / 160 KiB | > 3 / 6 / 320 KiB |
| `<img>` without width and height | 1 to 3 | 4+ |
| WebGL contexts live | | > 4 |
| Long tasks / blocking time | > 8 / 1.5s | > 20 / 4s |
| FCP / LCP | > 2.5 / 4.5s | > 4.5 / 8s |
| Layout shift | > 0.1 | > 0.25 |
| Module loaded, never mounted | 1 or 2 | 3+ |

Fixes: deferred modules; no scroll listeners beyond one passive read per frame written to a custom
property; no layout reads in move handlers; reserve space for counters and charts; preload the regular
and display font weights; `font-display: swap`; request only used weights. A page may set
`document.documentElement.dataset.ready = '1'` when its first screen is built.
Ours: the 72,670 row dataset must not ship as one big JSON on load; the top 500 table is fine.

## 16. Quality gate and checklist (`SKILL.md` section 5, `references/gate.md`)

The skill runs `scripts/gate.mjs` (headless Chrome, Node 22) and loops fix and recheck up to three
rounds until `GATE: PASS`; five waivers at most, each with a reason. We cannot run it as is (it
expects the starter's classes), but the checklist translates:

- [ ] First screen says what this is with one hard fact; the hero fills it alone at every width; its
      buttons inside it (hero-screen, hero-fill, fold-action, fold-cut).
- [ ] Every section 1 or 2 screens at 1440x900, h2 first and top aligned, no neighbour's heading or
      ground in its tile, nothing sparse, no section over 35% empty (section-height, one-section,
      section-air, empty-area, neighbour).
- [ ] Equal edges: every block on the wrap lines or column starts; no sideways scroll at 320 to 1440
      (container-edges, off-grid, right-edge, spill, off-viewport, stagger).
- [ ] Every visual draws at 1440, 1024, 768, 390; a refused effect shows its still (visual-empty,
      gl-fallback).
- [ ] No caption explains, apologises for or labels a picture; no placeholder or sample note.
- [ ] Motion: every button, link, linked card answers the pointer, nothing tilts; hero enters once on
      load; one or two moments; loops 2.5 to 4s; nothing moves on scroll except inside a moment's own
      section; anything moving past 5s has a pause button; under reduced motion everything rests and
      nothing stays hidden; at most four WebGL contexts.
- [ ] Keyboard and head: named controls, alt text, heading order, no positive tabindex, skip link first,
      focus ring visible at once and never under the header, lang, title, description, share tags.
- [ ] One system: one button pair, one card style, one radius scale, one link look; two boxes deep at
      most; one heading scale; fonts actually loaded (font-load); text contrast 7:1 body, 4.5:1 muted.
- [ ] Copy: headings name things, buttons a verb and an object, at most two hero actions, one fact one
      wording, no slop word or stock line, devices within budget; a voice of its own.
- [ ] Fast: no FAIL row in the perf table.
- [ ] 820, 768, 390, 320: sections on their screens; nothing lies on anything else or under the fixed
      bar (collide); 44px targets; one column at 390; buttons full width.
- [ ] Your eyes: "beside the figma.com and x.ai frames it reads as professional; nothing tilted,
      staggered, cut or overlapping; the hero is the work, not a mood."

Checks we can borrow by hand: screenshot at scrollY = k x 900 (the judge tile) and at 1440, 1024,
820x1180, 768x1024, 390x844; read each tile for one section only. Run the copy through the lint word
lists above. Look at reduced motion once.

## 17. "Never" list (whole skill, consolidated)

- A card, row or tile that fades in on scroll; a fade in on every section; parallax on text; scroll
  jacking; random blinking.
- Stock pictures passed off as the subject; invented reviews, quotes, customers or figures.
- Violet or lavender in the page's own design.
- Copying a reference site's code, copy, pictures or signature effect.
- A drawn look alike of a real logo (IBM's mark: use the real file or none).
- Glass, frosted panels, `backdrop-filter`, glows round buttons, glossy 3D blobs.
- A loader, an entry gate, a delay before reading.
- Text in a box in a box; a widget floating dead centre with even ground all round.
- A pattern (grid, ruling, contours, dots) behind a window, a list or a chart's text.
- A fade over the point of a visual; a sliver of 1 to 23px at any edge.
- Small grey text (14 or 15px muted) for anything people read.
- A big stat strip of invented KPIs; a logo wall; check icon lists.
- Tabs, accordions, carousels on anything but a software tour (click only).

## 18. Not applicable to our page (one line each)

- Kind classification, the dealers (`deal.mjs`, `start.mjs`, `moments.mjs pick`) and their histories: we choose by brief, not by dice.
- Places, cafes, rooms, menus, opening hours, `dl.hours`, open now lines: no venue.
- Addresses, maps, `fx-map`, OpenStreetMap links, phone rules, imprint and VAT rules: no contact data.
- Main action word for word in nav, hero, close and phone bar; the phone action bar: no transaction.
- Booking form, newsletter, form endpoints and success lines: no form.
- Pricing cards, plans, line ups, "from" prices, swatches, order cards: nothing sold.
- Photographs library, photo credits line, stand in photos, `photos.mjs`, photo chapters: no photos (unless we add some).
- Product renders, 3D prints, dither objects, `assets/objects`: skipped by brief.
- UI fragments, `app-frame`, `window`, `diff-review` etc.: no software product to show.
- Real brand icons via `icons.mjs`: only if we show IBM or CVE source logos.
- Gaming rules (key art, store icons, trailer slots).
- Big scenes (`assets/scenes`): need the client's photographs or screens; only `letter-physics`, `dot-becomes-the-full-stop` (statement scenes, no WebGL) could fit, as the page's one effect.
- Footer types and closes as sales devices (`close-type` with an XL buy button): we can keep the shape (one big line, one button such as "Read the method") but not the sales job.
- The gate's Stop hook, waivers file and rounds: tooling for their starter kit, not our static page.
- Words per screen of 34 to 47 for other kinds: we use the tech budget (60 to 80).
- Nav mega menus and picture cards: a one page story needs at most a slim chapter nav.

## 19. Reusable code: what to copy and what each needs

| File(s) | What it gives us | Needs |
|---|---|---|
| `assets/motion/motion.css`, `motion.js` (module, 25 KB + 23 KB) | hover, press, underline draw, focus ring, hero entrance with word masks, reduced motion | `system.css` tokens (`--ink`, `--accent`, `--action`, `--line`, `--r-btn`...), `ui/cards.css`, `<html data-motion>`; easier to port the numbers than the files |
| `assets/moments/moments.js`, `lib.js` (11 KB) + `word-highlight/`, `pinned-chapters/`, `counter-rolls/`, `letters-assemble/` | scroll scrubbed statement, pinned step walk, odometer figures | page tokens on `:root`; served over http; no other deps; head lines in section 7 |
| `assets/effects/fx.js` + one `<id>/effect.js` | a WebGL or canvas ground with fallback, pause, DPR cap | ES modules over http; palette CSS vars; `data-fx`, `data-fx-seed`, `data-fx-params` |
| `assets/components/shared.js` (`still`, `fill`, `windows`, `pauser`) | bake an effect into a still picture; fill digits; pause disc | imports `effects/fx.js` |
| `assets/components/fx-chart/`, `fx-bars/`, `fx-stat/` | accessible chart patterns (keyboard reading, live region, hidden table, ring on latest bar) | `system.css`, `components/base.css`, `shared.js`, `fx.js` |
| `assets/diagrams/diagram.js`, `diagram.css`, `mount.js`, `presets.json` | node and line diagram with pulse | local icon files if icons used |
| `assets/backgrounds/backgrounds.css`, `backgrounds.js` | 16 CSS grounds (`bg-horizon`, `bg-deep`, `bg-halo`, `bg-ruled`, `bg-dots`, `bg-arcs`...) | page tokens; link after `system.css` |
| `assets/layout/hero-statement.html`, `hero-word.html`, `hero-centred.html` | hero markup to study | `layout.css`, `layout.js`, `system.css` |
| `library/palettes.json`, `library/type.json` | 64 palettes and 39 Google Fonts pairings with tracking | data only |

All MIT. Everything is plain static files with no build step and no CDN, which matches our limits;
the catch is the shared token layer in `system.css` (103 KB), so the realistic plan is to lift the
moments and selected effects, and reimplement the motion numbers in our own CSS.

## 20. The ten rules that matter most for "Before the Breach"

1. One section per screen at 1440x900 (or exactly two), h2 first and top aligned, no neighbour peeking.
2. Scroll moves nothing except inside named story sections, scrubbed and reversible, finished at both ends; no fade ins on cards, rows, prose or the table.
3. The hero enters once: lines 700ms each, 80ms apart, rest fades up 12px at 520ms, 60ms apart, `cubic-bezier(.22,1,.36,1)`, about 1.1s total, no loader.
4. UI ease `cubic-bezier(.2,.8,.2,1)`; hover 150 in / 120 out / 90 press; lift 2px, step 1px, press scale .985; no overshoot; transform and opacity only.
5. One effect, at most two moments, one count, four WebGL contexts; everything has a still fallback and reduced motion shows the finished state.
6. Two text lines (left line and one split line), 12 columns, 24px gutter, 1280 wrap; text left and visual right on every split.
7. Type: one or two families (not Inter, Roboto, Space Grotesk...), weights 400 and 500 only, tight tracking on big type, body 16/26 at 7:1, nothing under 13px, lines under 62 characters.
8. Colour 90 to 95% neutral, one accent under 3% of a screen, never violet, never `#000`, highlight by contrast not marker colour.
9. Copy: a hard fact on the first screen, a noun in every heading, buttons as a verb and an object, numbers in sentences, 60 to 80 words a screen, no slop words or stock lines, device budgets kept.
10. No captions, no invented figures, no stat strip of labels, no glass, no logo marquee, no scroll cue, no eyebrow numbering.
