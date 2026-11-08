# Impeccable: design rules digest for "Before the Breach"

Source: https://github.com/pbakaus/impeccable (Paul Bakaus, Apache 2.0), cloned and read in full: README, skill/SKILL.src.md, every skill/reference/*.md, skill/agents/*.md, plus the detector rule catalog (crates/live/assets/antipatterns.json, 62 rules). Impeccable started from Anthropic's frontend-design skill. It is a set of "commands" (typeset, colorize, layout, animate, delight, bolder, quieter, distill, clarify, polish, harden, adapt, optimize, overdrive, critique, audit...) each with a playbook, plus a "craft floor" of bans and a deterministic slop detector.

This digest keeps exact values and marks what does not fit our page as "not applicable" (N/A).

Our page, for reference: one static page (HTML/CSS/JS, no build step, restricted CDNs), a scroll driven data story. 72,670 vulnerabilities ranked; 75 attacked ones in the test years; a Guardian style thread fan chart; rate bars; results; a top 500 table; FAQ. Audience: lay judges, partly on a projector. Must be unique, tasteful, animated.

---

## 0. How Impeccable frames the job

- Work like "an award winning design director": production grade code, a clear point of view, a deep grasp of what the client and users need, exceptional craft.
- Finish the job. No hedging, no shortcuts: the deliverable is complete.
- Verify by looking at the rendered result at the sizes it ships at. Batch checks: fix everything one look shows before looking again, rather than screenshotting after every tweak. Two inspection rounds is the ceiling.
- The brief wins. Pinned aesthetics, eras, materials, fonts and palettes beat any "saturated pattern" warning. Redirecting a clear brief toward your own taste is failure.
- Loaded symbols stay out of decoration (militarist or hate emblems as motifs). Low risk for us, but no "skull and crossbones" or military insignia as cyber decoration either; keep to neutral forms.
- Truth binds claims, not demonstrations. Illustrative material may be authored at full fidelity but must be labelled synthetic wherever a visitor could mistake it for real. Claims (prices, customers, benchmarks, capabilities) are never invented. For us: every number on the page must come from our data; any illustrative example (a fake CVE card, a mock row) must say so.

### Modes (pick by surface, not product)

| Mode | Visitor success | Ambition shows as |
|---|---|---|
| Persuade | decides and acts (landing, campaign) | bold, distinct work with a point of view |
| Operate | completes a task (app, dashboard, tool) | precision, restraint, familiar patterns |
| Read | understands something (docs, articles, guides) | structure for comprehension, then make reading worth staying for |
| Experience | is inside the work (portfolio, showcase) | the artifact leads from the first viewport |

Our page is a Read surface (judges must understand a method and a result) with Persuade stakes (they score it) and an Experience opening (the fan chart can lead). Practical consequence used through this digest: the frame (masthead, section openers, chart staging, motion) may commit fully to a world; the reading column stays calm, real measure, real contrast, nothing performing behind body text.

Read mode specifics (mode-read.md):
- "The world owns the frame and serves the column." Frame = masthead, navigation, ground, title and section openers, how tables, code and callouts are set. Column = reading face, real contrast, real measure (about 60 to 75 characters, body near 16px).
- Monospace is for code, parameters and small labels, never running text or headings by default.
- Tables, notes and figures sit in standard forms readers already know, set in the world's type and palette.
- The signature move is one system used where it earns its place, never a frame repeated around every element.
- Self check: can a reader tell where they are and where to go next? Cover the name: could this be anyone else's page? If yes, push the frame further into the world. If it reads as an artifact before it reads as a document, pull the world back out of the column.
- Good sources for Read worlds: reference books, type specimens, timetables, field guides, technical manuals, scholarly apparatus, a newspaper's wayfinding. A tool or fictional interface from the audience's world (terminal, radar, SOC console) comes back as a costume: take only type, palette, density and one signature move from it.

Persuade specifics that still apply (mode-persuade.md):
- The opening must make the offer intelligible and desirable and demonstrate something only this product can prove. For us: the first viewport should show the ranking idea working, not a title card.
- The world may carry the page, never be a picture of it. A viewport painted whole as a poster with no working parts is a failure; so is the generic product page (headline, subcopy, button, row of equal cards). A split hero or a centred headline over a row of cards is "the template whatever world paints it".
- Sections keep a steady vertical rhythm; the section below starts as a section, not more painting.

---

## 1. Choosing a visual world (new-work.md, condensed)

The full flow uses a dice roll script and decision page (N/A: tooling). The thinking transfers:

1. Name the product's unique mechanism in one sentence, the audience's real scene, its cultural home, and what the first surface must prove.
2. Name the page this category always ships and its predictable opposite. Both are "the rut". For a cyber data story the rut is: near black ground, neon green or cyan, glowing edges, terminal mono, hex rain, padlock icons. Its predictable opposite is: cream newspaper, hairline rules, italic serif.
3. List seven concrete visual systems, artifacts, places or rituals the audience knows by heart, each with why it resonates and how it looks (ground and main colours, type voices, one signature). Span at least three material families. On a Read surface, never draw them from the tools the audience operates (terminal, scope, control panel).
4. Ask what this would look like as a physical object, and what its world looked like before the web.
5. Commit to one direction. Write it down before code as a contract (see section 1.2).

### 1.1 Colour strategy (pick before picking colours)

- Restrained: neutrals tinted from the world plus one accent.
- Committed: one saturated colour carries 30 to 60% of the surface.
- Full palette: 3 to 4 named roles.
- Drenched: the surface IS the colour.
- Colour commits at page scale: fields that own whole regions, not accents scattered on neutral.
- Dark or light is never a default. Write one sentence of physical scene (who, where, under what light) and let it force the answer. For us: judges in a lit room, part of them on a projector. Projectors wash out dark greys and thin strokes (our inference, consistent with the rule). This argues for a ground and stroke weights tested on a projector, not chosen by "cyber means dark".

### 1.2 Typeface choice

- Choose faces like objects from the subject's world. Persuade and Experience want faces with a point of view; Read and Operate are well served by workhorse faces.
- Reflex faces that mean "you stopped looking": Fraunces, Playfair Display, Cormorant, Lora, Crimson, Newsreader, Syne, Space Grotesk, Space Mono, IBM Plex, Inter as display, DM Sans, DM Serif, Outfit, Plus Jakarta Sans, Instrument Sans. Using one needs a reason no other face could satisfy, and a subject association is never that reason ("tech wants a mono" is exactly what the list breaks). For us: IBM Plex is IBM's own brand face, so it is tempting. Under these rules it needs a stated reason beyond "it's IBM"; the brief does not pin it. Treat Plex as a deliberate decision, not a default. Detector rule `overused-font` also flags Inter, Roboto, Fraunces, Geist, Plus Jakarta Sans, Space Grotesk.
- No system display face (Impact, Arial Black, the platform sans) as the display voice: source and self host a face. With our restricted CDNs, Google Fonts stylesheets are allowed; self hosting the woff2 beside the page is the safest path either way.

### 1.3 Calibration: the four saturated "AI looks"

Generated interfaces cluster around these regardless of subject. Legitimate when the brief asks; where the aesthetic is free, landing in one means the self check failed:

1. Warm cream ground, high contrast serif display, terracotta or signal red accent.
2. Near black with one neon accent and glowing edges.
3. Broadsheet editorial hairlines, italic display serif, small tracked mono labels.
4. Flat saturated ink with black boxes, hard offset shadows, heavy condensed display type.

Test: if someone could guess your aesthetic from the category alone, or from category plus avoidance, rework. WARNING for us: "Guardian style" invites look 3, and "cybersecurity" invites look 2. Borrow the Guardian's chart grammar (thread fan, annotation, honesty), not its costume of hairlines plus italic serif plus tracked mono labels.

Also: energy is not the enemy of trust. Negative constraints rule out devices, not exuberance. Claude specific note in the source: Claude's rendition prior drifts to cream grounds, serif display with italic accents, and lamplight. Treat that first palette as already spent.

### 1.4 The direction contract (write before code, about 150 words)

- THESIS: the one idea this surface owns, and the category default it refuses.
- OWN-WORLD: palette and component language, recognisable with all content removed.
- STORY: what the visitor understands, believes, does.
- FIRST VIEWPORT: exact composition, what is where at what scale, where the primary action sits.
- FORM: the chosen form and its rank in your list.
- FINISH: unreviewed and undocumented is unfinished. "If a block reads like a mood, the direction is not decided yet." Never ship the contract inside the page (no HTML comments, hidden DOM, data attributes).

### 1.5 Build rules for both paths

- The first viewport is a thesis, not a header. Demonstrate the mechanism immediately, at the scale the form has in life. Memory test: if someone left after one viewport, what would they describe an hour later? If the honest answer is a mood, the concept has not committed.
- Prove, don't claim. Show the subject doing its job, specifics a competitor could not copy paste.
- Author the assets; never substitute chrome. Gradients, glass, generic icon tiles and many vertex clip-path polygons where real content belongs are "the gap wearing chrome".
- Build the form's web leverage: if the world names a technique (canvas, view transitions, generative motion), build the technique, not a static imitation.
- Pace the scroll like a studio: vary density, scale, image, motion and quiet inside one grammar; a dense passage earns a quiet one; the page ends anchored by a real close. One spacing rhythm throughout, more space above a heading than below it.
- Author motion as material: the form's native motion once, orchestrated, not scattered hover effects. Keep content visible by default.
- Commit every atom: nav, buttons, inputs and links are rebuilt in the form's vocabulary; a stock component inside a committed form is a lapse. Land the first build fully committed; later passes clarify, never dilute.
- In unattended work, "the safe rendition is the known risk".

Comp led build path (image generation, plates, region maps, hero gate at 72%): N/A, we build code led. The comp discipline still offers two useful tests: "Busy is louder, not bolder" (one dominant move, the rest holds still), and "a second element competing with the lead at the same scale is the comp shouting".

---

## 2. Typography (typeset.md, craft-floor.md)

Assess, answering each with a selector or computed value:
- Authority and fit: which faces, weights, roles? Defaults or chosen? Is every family necessary?
- Hierarchy: can heading, body, label, metadata and data roles be told apart at a glance? Are adjacent sizes or weights too close to carry different jobs?
- Scale: a deliberate role scale or arbitrary values? Do repeated roles stay identical?
- Reading: body within 45 to 75 characters; line height, rhythm, contrast and tracking tuned to the actual face, width and surface.
- Stress: long headings, zoom, narrow containers, missing weights, font fallback.
- Delivery: only used assets loaded; fallback metrics avoid invisible text and reflow.

Set the system before editing: the roles, the contrast between roles, reading measure and density, authoritative faces and weights, constraints. Use the fewest roles and families that make hierarchy unmistakable. Combine size, weight, space and tone; do not ask size alone to do all the work. Name tokens by purpose, not value.

Apply:
- Body floor 1rem / 16px on the web.
- Prose 45 to 75ch (craft floor says 65 to 75ch). Wider lines need more leading.
- Light text on dark: compensate on three axes: slightly more line height, a touch more tracking, one step more weight if the face needs it.
- Tune line height to face, width and contrast, not a universal ratio. Detector floor: below 1.3x is `tight-leading`; body 1.5 to 1.7.
- Use numeric, tabular, code and label features when content benefits: `font-variant-numeric: tabular-nums` in the rate bars and the top 500 table.
- Load only used weights; metric compatible fallbacks; never block text (`font-display: swap` or `optional`, subset with `unicode-range`, preload the critical face).
- Marketing display type may respond to space (clamp); dense reading surfaces stay predictable.
- Preserve browser zoom and user font settings.
- Paragraph rhythm: paragraph spacing OR first line indent, not both.
- Never make type decorative at the expense of comprehension; no second family without a role only it can perform.

Line breaks (after Butterick's Practical Typography):
- `text-wrap: balance` on headings and short centred blocks; `text-wrap: pretty` on body copy. Both are progressive.
- `pretty` fixes a lone last word; a two word tail is fine.
- In a column too narrow for either, edit the copy or widen the column.
- Hand break a heading only between phrases and check at every width; a hard break landing mid line on a phone is worse than default wrap.
- A deliberate uneven break (one word for weight, a poster line) is allowed but rare.

Craft floor type limits (exact):
- Body measure 65 to 75ch.
- Display max 6rem.
- Tracking floor -0.04em; -0.02 to -0.03em usually reads better.
- Balanced headings, obvious scale and weight steps.
- Run the real copy at every breakpoint and fix what overflows.

Detector thresholds worth designing to:
- `flat-type-hierarchy`: heading and body roles separated by less than 1.25x at every step.
- `tiny-text`: body under 12px (use at least 14px, 16px ideal).
- `undersized-ui-text`: functional text (links, buttons, labels, table cells, meta rows) under 11px; 10px only for non interactive legal smallprint. Chart axis labels and table cells count.
- `wide-tracking`: above 0.05em on body text. Wide tracking only for short uppercase labels.
- `all-caps-body`: 80+ characters in caps.
- `line-length`: lines over about 80 characters; add max-width 65ch to 75ch.
- `justified-text` in a narrow column without hyphenation.
- `oversized-h1`: a full sentence headline at display size dominating the viewport. One or two words at that size is fine.
- `extreme-negative-tracking`.
- `italic-serif-display`: oversized italic serif hero headline (editorial register may want it; judge by context).

Operate mode type notes (for our table and FAQ, which behave like UI):
- One family is often right for UI; tighter scale ratio 1.125 to 1.2 between steps; fixed rem scale for UI parts rather than fluid; data tables may run denser (120ch+ is fine).

Verify: primary, secondary, body and metadata roles recognisable without reading; long text comfortable at every width; loading creates no reflow or invisible text; zoom and reduced viewport paths usable.

N/A: live mode `--p-scale` params; Dynamic Type and native scaling; localisation expansion beyond English (one page, English only; still allow long words like "vulnerabilities" to wrap on phones).

---

## 3. Colour (colorize.md, craft-floor.md, quieter.md)

- Introduce colour as hierarchy, meaning and atmosphere. Read mode: colour primarily encodes reading hierarchy, wayfinding and status; rarity gives an accent force. Persuade or Experience: colour may own large regions.
- Name the emotional temperature, dominant relationship, contrast range and dosage before editing.
- Build roles, not a bag of swatches: canvas and elevated surfaces; primary and secondary text; action, focus and selection; borders and separators; success, warning, error, information; data categories or scales.
- For a new web palette prefer OKLCH (predictable lightness and chroma). Choose hue from product meaning and the visual direction, never from a default category association (security is not automatically green on black or red alert).
- Let the strongest colour own a deliberate region or role rather than scattering tiny accents.
- Do not spend the action colour on decoration.
- Tint neutrals only when the brand hue genuinely creates cohesion; neutral grey is valid.
- On coloured surfaces derive secondary text from the surface hue or foreground; never washed out grey (detector: `gray-on-color`).
- For data: distinct lightness, chroma, shape, label or pattern so colour is never the only code. For us: the 75 attacked threads vs the rest must differ in more than hue (weight, opacity, label).
- Dark mode: design surface elevation and contrast explicitly; never invert mechanically. Each theme composed.
- Prefer explicit colours over chains of translucent overlays (alpha makes contrast context dependent).
- OKLCH ramps: vary lightness and reduce chroma near white and black.
- "Decoration without a relationship to hierarchy, state, content, or the visual world is not a colour strategy."

Contrast (WCAG AA, verify computed pairs, all states, both themes, text on images):

| Content | Minimum |
|---|---|
| body text (and placeholder) | 4.5:1 |
| large text | 3:1 |
| controls, icons, focus indicators | 3:1 |
| AAA body | 7:1 |

Also simulate common colour vision deficiencies. For a projector, aim above the minimums (our note).

Quieter's colour values (use if the page gets loud):
- Saturation 70 to 85% instead of full; neutrals do most of the work with colour as accent (the "10% rule"); high contrast only where it matters most; tinted greys rather than pure grey; never grey text on colour (use a darker shade of that colour or transparency).

Operate notes that apply to our interactive parts: a standard state vocabulary (hover, focus, active, disabled, selected); accent for current selection and state only; no full saturation accents on inactive states.

Detector colour rules: `ai-color-palette` (purple or violet gradients, cyan on dark; flat neon on dark once a second tell hue joins), `cream-palette` (warm cream or beige page ground by reflex), `low-contrast`, `gray-on-color`, `dark-glow`, `radial-halo`, `radial-spotlight-glow`, `gradient-text`.

N/A: live mode `--p-color-amount`; DESIGN.md token sidecars (optional for us).

---

## 4. Layout and spacing (layout.md, distill.md, craft-floor.md)

Assess with evidence:
- Reading order, squint test: with detail blurred, can you still find the primary element, the secondary, and the major groups, in order?
- Grouping: related items close, distinct groups separated, or are containers compensating for weak proximity?
- Rhythm: do tight and generous intervals make a cadence, or is one value repeated until everything weighs the same (detector `monotonous-spacing`)?
- Structure: does topology match content? Are repeated cards or columns genuinely equivalent, or a framework default?
- Density: does information per region fit the task and mode?
- Adaptation: what reorders, collapses, wraps, scrolls or stays fixed at narrow, wide and zoomed sizes? Does DOM and focus order agree with visual order?
- Extremes: long content, sticky elements, small touch targets.

Set a spatial thesis: primary reading path; what belongs together and what separates; what leads and what supports; intended density and rhythm; how it changes across viewports.

Apply:
- Group by meaning; use proximity before containers or decoration.
- Rhythm through deliberate contrast between tight and generous intervals.
- A documented spacing scale, not one off values. A 4 unit base gives useful middle steps that an 8 only scale misses.
- Hierarchy follows priority, not framework defaults.
- Responsive behaviour is structural: reorder, collapse, reflow, reveal.
- Container aware components when one component appears in several contexts.
- `gap` for sibling rhythm instead of child margins.
- Touch targets usable even when visible marks are small (chart hit areas larger than the line).
- Depth only when it clarifies state or hierarchy.
- Optical corrections only after looking at the render.
- "Variation is not a goal by itself." Break repetition only when content or priority changes.

Craft floor spacing: tight groups, generous separation, more space above a heading than below it (detector `heading-rhythm`). Read the computed values.

Distill's layout and visual limits (useful targets):
- 1 to 2 colours plus neutrals, not 5 to 7.
- One font family, 3 to 4 sizes maximum, 2 to 3 weights (as a distill target; a display plus body pair is fine if each has a role).
- Never nest cards in cards; cards are not needed for basic layout; use spacing and alignment.
- Linear flow over complex grids where possible; remove sidebars; consistent alignment (pick left or centre and stick to it); generous white space.

Cognitive load numbers (critique.md) that shape our sections:
- Chunk information in groups of 4 or fewer.
- 4 or fewer visible options at any decision point; 5 to 7 is the boundary; 8+ overloaded.
- One primary element, 2 to 3 secondary, everything else muted.
- Long form: one reading path; gather related links into one block at the end, not scattered mid flow.

Detector layout rules: `nested-cards`, `monotonous-spacing`, `cramped-padding` (at least 8px, ideally 12 to 16px inside bordered or coloured containers), `body-text-viewport-edge` (16px gutter, 12px at 480px wide or narrower; ideally 24 to 32px), `text-overflow`, `text-occlusion`, `first-viewport-column-overflow`, `edge-flush-cards`, `clipped-overflow-container`, `skipped-heading`, `heading-rhythm`, `repeated-container-text`.

N/A: live mode `--p-density`; safe area and native navigation (only the web viewport meta matters).

---

## 5. Motion (animate.md, craft-floor.md, overdrive.md, optimize.md)

Principle: motion explains state, relationship and hierarchy, or makes one authored moment the surface has earned. Decoration without purpose is "animation debt".

Mode: Persuade and Experience may let motion carry the voice: "prefer one rehearsed focal sequence to repeated section reveals". Read and Operate: motion serves feedback, state and continuity; do not make people wait through page load choreography.

Find the job. Motion only where it:
- acknowledges an action;
- makes a state change or spatial relationship legible;
- preserves continuity through a layout change;
- directs attention at a meaningful moment;
- embodies the visual world. Do not animate a static area merely because it exists.

Motion thesis (write it first):
- Focal moment: the one sequence that deserves authorship. For us: the fan chart threads drawing out and the 75 attacked ones surfacing. "A generic fade and rise, hover lift, parallax layer, or scroll reveal is not a thesis."
- Continuity: the state changes that need explanation (chart steps as the reader scrolls).
- Feedback: controls that need acknowledgement (table sort, FAQ open, chart hover).
- Budget: which effects are expensive and how often they run.

Material by meaning:
- Continuity and relationship: shared element motion, FLIP transforms, view transitions, deliberate spatial movement.
- Focus and depth: bounded blur, filter, backdrop, light or shadow changes.
- Reveal and composition: masks, clip paths, cropping, controlled occlusion.
- Material and energy: colour, gradient position, texture, distortion, shaders where supported.
- State and feedback: the smallest change that makes cause and result unmistakable. "Do not stack techniques for spectacle. One strong material idea, carried through the focal sequence and quiet supporting states, is usually enough."

Stagger: appropriate when a list appears as a list. Cap the total delay. Never reinterpret every scrolled section as a staggered list.

Timing (exact):

| Duration | Use |
|---|---|
| 100 to 150 ms | immediate feedback |
| 150 to 300 ms | routine state change |
| 300 to 500 ms | layout, overlay or view transition |
| 500 to 800 ms | a deliberately authored focal entrance |

- Exit faster than entrance.
- Easing: natural deceleration, `cubic-bezier(0.16, 1, 0.3, 1)` for confident arrivals; exponential ease out (quart, quint, expo). No bounce or elastic by reflex (detector `bounce-easing`).
- Long feedback feels like latency. Operate guidance: 150 to 250 ms on most transitions.
- Quieter's numbers: shorter distances (10 to 20px instead of 40px), ease out quart, never bounce.

Implement to the runtime:
- CSS transitions and keyframes for declarative state and bounded sequences.
- Web Animations API for interruption, sequencing and dynamic values.
- View Transitions when continuity across states is the point.
- Scroll driven motion only when the scroll relationship itself carries meaning, with a robust fallback. This is our case: scrollytelling steps genuinely map scroll to chart state.
- Do not add a dependency for an effect the stack can express (fits our CDN limits).
- Keep content visible in the default state so failed scripts do not hide the page (detector `content-hidden-at-rest` is an error level rule; `script-error` too).
- Avoid animating `width`, `height`, `top`, `left`, margins; use FLIP, transforms or grid techniques. For rate bars: animate `transform: scaleX()` from a set origin, not width.
- Bound blur, filter, shadow, canvas and shader work to isolated regions.
- `will-change` only during a known animation; never left on at rest or applied broadly.
- Measure on target devices; transform is not automatically fast.

Accessibility:
- Respect autoplay and sound preferences; any non essential loop stops when offscreen or hidden.
- Every web animation needs a `prefers-reduced-motion` path with an intentional alternative: remove or reduce spatial movement while keeping opacity, colour and state transitions that carry meaning. "Reduced motion means fewer and gentler animations, not disabling all motion." The audit flags a global `0.01ms` kill switch that destroys useful feedback, and flashing above threshold.
- For us: with reduced motion, the fan chart should still step through states (crossfade), not jump to the end or freeze.

Craft floor motion: one authored moment, not scattered effects, and not one identical entrance on every section. Exponential ease out from an already visible default. Reach past transform and opacity: blur, backdrop-filter, clip-path, mask and shadow belong to the palette when smooth.

Overdrive toolkit (ambition, use one, not several):
- `@starting-style` (all browsers) animates from `display: none`.
- Scroll driven animations `animation-timeline: scroll()` (Chrome, Edge, Safari; Firefox behind a flag): always wrap in `@supports (animation-timeline: scroll())` and give a static fallback. For a projector demo in an unknown browser, an IntersectionObserver plus rAF driven version is safer.
- `@property` to animate registered custom properties (gradients, colours, numbers, e.g. a counting figure).
- Canvas 2D for many marks (72,670 threads is too many SVG nodes; canvas or a sampled subset).
- Animated data transitions: morph between chart states rather than replacing.
- Performance: target 60fps; below 50, simplify. 16ms per frame. Lazy initialise heavy things near the viewport; pause offscreen rendering. Use `requestAnimationFrame`; throttle scroll handlers (100ms example) or use IntersectionObserver.
- NEVER: jank on mid range devices; bleeding edge APIs without fallback; sound without opt in; using technical ambition to mask weak fundamentals; layering multiple competing extraordinary moments ("focus creates impact, excess creates noise").
- Tests: the wow test (show someone fresh), the removal test (take it away: does anyone miss it?), the device test, the context test.

Verify: the focal motion is specific to this world; every supporting animation explains feedback, state or relationship; interruption and repeat use behave; reduced motion keeps meaning; removing an animation would lose meaning, not merely decoration.

Detector motion rules: `bounce-easing`, `pulsing-dot` (only for genuinely live data), `marquee`, `blinking-cursor` (fake typing prompt in a hero), `content-hidden-at-rest`.

N/A: WebGPU, WASM, Web Audio, device APIs, spring libraries (no build step; avoid unless tiny).

---

## 6. Delight (delight.md)

- Delight is product character revealed through a useful interaction, a humane response, or an unexpectedly considered detail; not a layer of generic whimsy.
- Look for: effort worth acknowledging; waiting that can become informative; an interaction whose response can express the brand; a useful capability people enjoy discovering.
- Define one delight thesis in one sentence: what the user should feel and why it belongs to this product. Then the smallest system that delivers it: a distinctive response to a meaningful action, product specific language, a recognisable material behaviour, an environmental detail, a discovery reward that reveals real utility.
- Copy uses the product's language; "generic whimsy is worse than neutral clarity".
- Delight must not: delay or obscure the primary task; override accessibility; add unrequested factual claims; play sound without consent; become exhausting on repeat; cost disproportionate assets.
- Verify: specific enough that a neighbouring product could not use it unchanged; improves comprehension or confidence; page stays fast and obvious without it.
- Ideas consistent with the rules for us: hovering a thread names the CVE and its rank; a judge can type or pick a well known vulnerability and see where it ranked (discovery that reveals utility); the FAQ answering in plain words. Not: confetti, fake hacking text, glitch effects.

N/A: success, waiting, empty and error emotional moments (no accounts or forms); haptics.

---

## 7. Bolder, quieter, distill (the three steering moves)

### Bolder
- Scope is sovereign: touch only the named target; add no new colours, fonts, radii, shadows or primitives the system does not already own.
- A flat section usually opts out of the system's own strongest moves. Bring it up to the expressive level its neighbours reach, in the system's own vocabulary.
- Reject "more effects" first: that is the opposite of bold.
- Commit, then clarify: make one decisive move completely, then quiet everything around it. "If every element got louder, the section got flatter."
- Give it its own rhythm: a peak in the scroll, a shift in density or pace.
- Skeleton test: strip the copy; does the bare structure still say what the section is and why it matters? If it only works once words return, the boldness is in the text size, not the design.
- Keep content true.

### Quieter
- "Quiet design is harder than bold design." Reduce intensity without going generic.
- Intensity sources: saturation, contrast extremes, too many heavy elements, animation excess, too many decorations, everything large.
- Values: saturation to 70 to 85%; weights 900 to 600, 700 to 500; thinner or lower opacity borders or none; remove decorative gradients, shadows, patterns, glows, multiple shadows; motion distances 10 to 20px instead of 40px; ease out quart; reduce scale jumps; align rogue elements to the grid.
- Avoid: everything the same size and weight; removing all colour ("quiet is not greyscale"); removing personality; making everything small and light (some anchors needed).
- Generic quiet looks like "grey text on white, one sans at a uniform weight, and a grid of identical cards". Restraint still needs a point of view.

### Distill
- Remove anything that does not earn its place. Find the ONE primary goal; the 20% that delivers 80%.
- ONE primary action, few secondary, everything else tertiary or hidden; progressive disclosure (accordions, `<details>`) for complexity. For us: methodology detail and FAQ behind disclosure.
- Remove redundancy: if it is said elsewhere, do not repeat it; no headers restating intros.
- Content: shorter copy (cut filler, not meaning), active voice, no jargon, scannable structure, essential information only.
- Avoid: removing needed information; mystery as minimalism; oversimplifying a complex domain.
- "Perfection is achieved not when there is nothing more to add, but when there is nothing left to take away." (Saint Exupery)

---

## 8. Clarify: copy rules (clarify.md, distill.md, craft-floor.md)

- Read the whole path, not isolated strings. Find ambiguous nouns and verbs, internal jargon, vague labels, inconsistent terms and capitalisation, redundant headings and intros, tone that ignores stakes.
- Per state decide: the one fact the reader needs now; the next action; context that changes the decision; the tone. "Say each idea once. If the heading already explains the state, the introduction should add new information or disappear."
- Actions: specific verb plus object ("Sort by rank", "Show all 500"). Labels describe the outcome, not the gesture. Same noun and verb for the same concept throughout (pick "vulnerability" or "flaw" or "CVE" and hold it; define CVE, EPSS, KEV inline once).
- Plain language without flattening terms the audience truly knows; judges are lay, so define domain terms inline (cognitive load "jargon barrier": define unavoidable terms where they appear).
- Help text answers an implicit question rather than restating the control. Link text makes sense out of context; icon only controls need accessible names.
- Alt text conveys the image's information; empty alt for decoration. For charts: a text summary of what the chart shows.
- Do not rely on punctuation, colour or iconography alone to carry meaning.
- Keep numbers structured (format with `Intl.NumberFormat('en-US')` for 72,670).
- Maintain a short terminology glossary when inconsistency spans the page. "Do not vary words for literary effect in an interface."
- Copy is design material: the product's own language; controls name their action.
- Detector copy rules: `marketing-buzzword` (streamline, empower, supercharge, world class, enterprise grade, next generation, cutting edge...), `aphoristic-cadence` (three or more sections ending on "X. No Y." or "Not a feature. A platform."), `em-dash-overuse` (8+ em dashes at about one per 500 characters), `theater-slop-phrase` ("security theater" framing; relevant to our domain, avoid it).
- Final copy is as short as it can be without removing meaning.

N/A: forms, validation, error and permission messages, destructive confirmations, loading copy, localisation and pluralisation libraries (static English page).

---

## 9. Visualize and data viz

Note: Impeccable's `visualize.md` is about generating image comps before building, not about charts. That flow is N/A (we are code led). The data viz rules in the skill are spread across other files; collected here:

- A chart the page draws from data at runtime is a chart, not an illustration: inline SVG or canvas for data graphics is first class (the "real illustration or none" ban covers sketchy SVG scenes, never SVG doing geometry: crisp vector shapes, diagrams, animated linework).
- "Sparklines, progress rings, and soft shadowed rounded rectangles standing in for content" are refused. Every chart must carry real data and a reason.
- The hero metric template is refused: big number, small label, supporting stats, accent. For us: do not open with "72,670" in giant type plus three stat tiles. Show the 72,670 as the fan of threads.
- Colour is never the only code: use lightness, chroma, shape, label or pattern too.
- Data categories or scales are a colour role of their own; keep them separate from action colour.
- State colours sit on top of the palette only where they carry meaning (red critical, amber degraded, per mode-operate). A headline number that moves over time shows its recent history, with the onset marked when something changed (annotate the test years).
- Use tabular numerals in data.
- Large data: canvas or WebGL for datasets too big for SVG or DOM; virtual scrolling or pagination for long tables ("don't load all 10,000 items at once"). For our top 500 table: render all 500 is fine, but use `content-visibility: auto` or a "show more" step for performance and readability.
- Animated data transitions: morph between chart states rather than replacing.
- Responsive tables: transform to cards on mobile using `display: block` and `data-label`, or let the table scroll inside a container with a deliberate scroll affordance (detector `text-overflow` wants an intentional scroll, not a spill).
- Chart hit targets: 24x24 CSS px minimum (WCAG 2.5.8), 44x44 preferred for touch.
- Monospace only for data, code or measurement, never as a "technical" costume (CVE ids in mono is fine; headings in mono are not).
- Grid line backgrounds only on actual measuring surfaces: a chart's own gridlines are legitimate; a decorative page wide grid is `codex-grid-background`.

---

## 10. Polish (polish.md)

Polish is refinement, never concealed redesign. If the concept is wrong, say so instead.

Classify each drift: missing token; one off implementation; conceptual mismatch; local defect. Fix at the narrowest correct level.

Triage order:
1. Broken or blocked tasks, misleading state, inaccessible paths.
2. Missing states (loading, empty, error, success, disabled).
3. Flow, hierarchy, responsive and system drift.
4. Visual and motion inconsistencies.
5. Code and asset cleanup. "Do not perfect one corner while leaving the rest below the same quality bar."

Whole path checklist:
- Flow: primary story and current position obvious without flattening everything to equal weight.
- Layout and type: align to grid and spacing scale (optical as well as mathematical); same role type consistent; test measure, wrapping, zoom, font loading; verify every viewport, not just the current screenshot.
- Colour, imagery, icons: semantic tokens; contrast in every state; one icon family with consistent stroke, weight and optical alignment; prevent image layout shift (aspect ratios, dimensions).
- Interaction: every control has default, hover, focus, active, disabled, loading, error and success where they can occur; visible keyboard focus; logical tab order; labels; touch targets.
- Motion coherent, interruptible, performant; "do not add animation merely to make polish visible".
- Content and code: consistent terms, capitalisation, punctuation; remove debug output, dead code, unused styles.
- Finish: walk the path with mouse, keyboard and touch; mobile, intermediate and wide; console errors, layout shift, latency; then a source diff to remove accidental churn.

Browser surfaces (craft floor, "the one models skip most reliably"): theme text selection (`::selection`), the caret, custom scrollbars, focus rings (`:focus-visible`), underline offset (`text-underline-offset`), and the numerals in tabular data. These ship with browser defaults that belong to no design system.

---

## 11. Harden (harden.md)

Applicable to us:
- Extreme inputs: very long text (long CVE titles and vendor names in the table), large numbers (72,670; percentages with decimals), many items (500 rows), no data (a chart before its data loads).
- Text overflow tools:
  - Single line: `overflow: hidden; text-overflow: ellipsis; white-space: nowrap;`
  - Multi line: `display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;`
  - Wrap: `overflow-wrap: break-word; hyphens: auto;`
  - Flex items: `min-width: 0;` Grid items: `min-width: 0; min-height: 0;`
- Fluid type with `clamp()`; minimum 16px body on mobile, 14px only for genuinely secondary text; test zoom to 200%; containers expand with text.
- Use logical properties (`margin-inline-start`, `padding-inline`) as good hygiene.
- Number formatting with `Intl.NumberFormat`.
- Loading: if data is fetched (JSON or CSV), show what is loading and a clear failure message with a retry, and never leave the chart blank or the page hidden. Prefer inlining critical data.
- Graceful degradation: core content works without JavaScript (the story text, the key results, a static table); images have alt text; feature detection, not browser detection.
- Keyboard: all functionality reachable; logical tab order; skip link for long content.
- Screen readers: semantic HTML, live regions for dynamic changes (a chart caption that updates per step), descriptive alt text.
- High contrast mode: test Windows forced colours; do not rely on colour only.
- Memory: clean up listeners, timers, observers.
- Throttle scroll handlers (100ms), debounce input (300ms) for a table search.
- Interrupted gestures (if any custom drag or slider): clear drag state on `pointercancel`, `lostpointercapture` and `blur`; the next drag works without reload.
- Avoid: fixed widths for text; assuming perfect data; blocking the whole page when one component errors.

N/A: API status codes, auth, form validation and sanitisation, i18n (RTL, CJK, Arabic script, Persian digits and calendars), currency, pluralisation libraries, concurrent submissions, permission states, service workers and offline mode.

---

## 12. Adapt: responsive (adapt.md)

- Adaptation is rethinking for the context, not scaling pixels. Our contexts: projector (large, low contrast, viewed from distance, possibly 1280 or 1920 wide, mouse or clicker), laptop, phone.
- Mobile first: base styles for mobile, `min-width` queries layer complexity.
- Content driven breakpoints; three usually suffice (640, 768, 1024px). Generic ranges: mobile 320 to 767px, tablet 768 to 1023px, desktop 1024px+. Use `clamp()` for fluid values without breakpoints.
- Desktop: fixed widths with max-width constraints; "don't stretch to 4K". Show more upfront; richer visualisations.
- Mobile: single column, vertical stacking, full width components, 16px minimum text, progressive disclosure, touch targets 44x44px, thumb friendly, no hover dependent function.
- Detect input, not just size:
  - `@media (pointer: fine)` and `(pointer: coarse)` for target sizes (example paddings 8px 16px vs 12px 20px).
  - `@media (hover: hover)` for hover effects; `(hover: none)`: use active states instead.
  - "Don't rely on hover for functionality." Chart tooltips need a tap and keyboard equivalent.
- Safe areas: `padding: env(safe-area-inset-*)` with `max(1rem, env(safe-area-inset-bottom))`; meta viewport `width=device-width, initial-scale=1, viewport-fit=cover`.
- Responsive images: `srcset` with `w` descriptors plus `sizes`; `<picture>` for art direction.
- Tables to cards on mobile with `display: block` and `data-label`; `<details>/<summary>` for content that collapses on mobile.
- `display: none` still downloads; use sparingly.
- Test at 320px and very large screens, portrait and landscape; real devices where possible (DevTools misses real touch, CPU, font rendering, browser chrome). Chromium is not Safari.
- Avoid: hiding core content on mobile; assuming desktop means powerful; a different information architecture per context; forgetting landscape; ignoring touch on desktop.
- Audit touch target rule (WCAG 2.5.8): at least 24x24 CSS px unless spacing passes (a 24px circle centred on the target overlaps no other target); 44x44 recommended.

N/A: print and email adaptation (could add a light print stylesheet, optional), tablet master detail, native (adapt.native.md, ios.md, android.md).

---

## 13. Optimize: performance (optimize.md)

- Measure first; fix the actual bottleneck. Core Web Vitals targets: LCP < 2.5s, INP < 200ms, CLS < 0.1.
- Images: WebP or AVIF, right size, lazy load below the fold (never lazy load above the fold), 80 to 85% quality, `aspect-ratio` or dimensions set.
- Fonts: `font-display: swap` or `optional`; subset (`unicode-range: U+0020-007F` basic Latin); preload the critical face; limit weights.
- CSS: remove unused; `contain` and `content-visibility: auto` for long independent regions (the 500 row table, the FAQ).
- JS: defer non critical scripts; batch DOM reads then writes (avoid layout thrashing); rAF for JS animation; IntersectionObserver over scroll listeners; Web Workers for heavy computation (e.g. preparing 72,670 rows); break long tasks.
- Reduce requests: inline small critical assets, SVG sprites for icons, combine small files.
- Avoid: `will-change` everywhere; lazy loading above fold content; micro optimisation while ignoring the big bottleneck; forgetting mobile.

N/A: React memoisation, code splitting, GraphQL, CDN and SSR advice, RUM vendors.

---

## 14. Critique checklist (critique.md, adapted)

Run as two independent passes: (A) a design review by eye, then (B) mechanical evidence (detector, contrast, overflow). Do A first so mechanical findings do not anchor judgement.

A. Design review:
- Design specificity verdict first: is the composition, interaction and visual language grounded in THIS project, or could an unrelated product use it unchanged?
- Holistic: hierarchy, information architecture, emotional fit, discoverability, composition, typography, colour, accessibility, states, copy, edge cases.
- Cognitive load checklist (count failures: 0 to 1 good, 2 to 3 moderate, 4+ critical):
  - Single focus: no competing elements distract from the primary task.
  - Chunking: groups of 4 or fewer items.
  - Grouping: related items visually grouped.
  - Visual hierarchy: most important thing immediately clear.
  - One thing at a time: one decision before the next.
  - Minimal choices: 4 or fewer visible options per decision point.
  - Working memory: no need to remember something from a previous screen (for us: keep the legend and the key number visible while the chart steps change; "memory bridge" violation otherwise).
  - Progressive disclosure: complexity revealed when needed.
- Emotional journey: peak end rule (a strong peak and a strong end), emotional valleys, reassurance at high stakes moments.
- Nielsen's 10 heuristics, each scored 0 to 4 (4 means genuinely excellent; most real interfaces score 20 to 32 of 40). Heuristics 7 (Flexibility and efficiency) and 10 (Help and documentation) may be scored n/a on Persuade and Experience surfaces, renormalising the maximum (for example 24/32).
  1. Visibility of system status (for us: where am I in the story; chart step indicators).
  2. Match with the real world (plain language, natural order).
  3. User control and freedom (can I scroll back, skip the animation, jump to results?).
  4. Consistency and standards.
  5. Error prevention.
  6. Recognition rather than recall (labels on icons, visible legends).
  7. Flexibility and efficiency (n/a candidate; a "skip to results" link helps).
  8. Aesthetic and minimalist design.
  9. Error recovery.
  10. Help and documentation (the FAQ).
- Score bands out of 40: 36 to 40 Excellent; 28 to 35 Good; 20 to 27 Acceptable; 12 to 19 Poor; 0 to 11 Critical. With n/a: 90%+ Excellent, 70%+ Good, 50%+ Acceptable, 30%+ Poor.
- Report: 2 to 3 strengths, 3 to 5 priority issues tagged P0 to P3 (What, Why it matters, Fix), persona red flags, minor observations, provocative questions ("What would a confident version of this look like?").
- Severity: P0 blocking (prevents task completion), P1 major (significant difficulty or a WCAG AA failure), P2 minor (workaround exists), P3 polish. Tip: "Would a user contact support about this?" If yes, at least P1. Keep P3s few.
- Feedback style: direct, specific ("the submit button", not "some elements"), say what is wrong AND why it matters, concrete fixes, cut "consider exploring", prioritise ruthlessly, do not soften.

Personas (pick 2 to 3; for a landing or story page the table suggests Jordan, Riley, Casey):
- Jordan, confused first timer (our judges): first meaningful content obvious within 5 seconds; all icons labelled with text; no unexplained jargon; clear "what next". Red flags: icon only controls, jargon, ambiguous next steps.
- Sam, accessibility dependent: whole flow keyboard only; visible focus; alt text; 4.5:1 contrast; screen reader announces state changes; zoom to 200%. Red flags: click only interactions, meaning by colour alone, custom components that break reader flow, time limited content (auto advancing slides).
- Casey, distracted mobile user: thumb reach, state kept on return, works on slow 3G, touch targets 44x44pt, no heavy assets on load.
- Riley, stress tester: edges (0, 1, 1000 items, very long text), refresh mid scroll, features that look like they work but produce wrong results (a sort that does not sort, a number that does not match the table).
- Alex, power user: skippable animation, keyboard shortcuts (mostly n/a; a "skip intro" matters).
- Project persona to add: "The projector judge": sees the page from 4 metres on a washed out screen, someone else scrolls; red flags would be thin strokes, low contrast greys, text under 18px, motion that only makes sense if you are the one scrolling. (Our derivation, following the template.)

N/A: snapshot persistence, critique storage, trend lines, sub agent orchestration rules, overlay injection, desktop app CDP flow.

---

## 15. Audit checklist (audit.md)

Score each of 5 dimensions 0 to 4; total out of 20. Bands: 18 to 20 Excellent; 14 to 17 Good; 10 to 13 Acceptable; 6 to 9 Poor; 0 to 5 Critical.

1. Accessibility: contrast under 4.5:1 (3:1 large; 7:1 AAA); reduced motion has an intentional alternative (flag a global 0.01ms kill, flashing, motion blocking reading); ARIA roles, labels, states on interactive elements; keyboard focus indicators, tab order, no traps; semantic HTML (heading hierarchy, landmarks, buttons not divs); alt text. Score: 0 fails WCAG A; 1 major gaps; 2 partial; 3 AA mostly met; 4 AA fully met, approaching AAA.
2. Performance: layout thrashing; expensive animations (layout properties, unbounded blur or shadow, dropped frames); missing lazy loading; `will-change` overuse; unused dependencies.
3. Theming: hard coded colours not using tokens; broken dark mode; inconsistent tokens; values that do not update on theme change. For us: define colours as CSS custom properties on `:root`; if we offer dark mode, compose it.
4. Responsive: fixed widths; touch targets (24x24 CSS px WCAG 2.5.8 minimum, 44x44 recommended); broken touch on custom controls (`touch-action` on pointer drag surfaces); horizontal scroll on narrow viewports; text scaling; missing breakpoints.
5. Implementation integrity: repeated shortcuts, system drift, misleading or decorative content, a structure interchangeable with an unrelated product. Verify every detector finding in context; call out false positives.

Report: health table, integrity verdict, executive summary with P0 to P3 counts, findings with location, category, impact, WCAG reference, recommendation; systemic patterns; positive findings. Avoid: issues without impact, generic recommendations, skipping positives, everything P0, unverified false positives.

---

## 16. Finish review (agents/impeccable-finish-reviewer.md, adapted)

A fresh reviewer, not the builder, judges the finished page. Useful checks for us:
- Evidence: captures exist for desktop (1440 wide) and mobile (390 wide), plus the real projector width; no blank regions; entrance motion settled before capture (a hidden by animation element reads as missing and gets "fixed" into a regression).
- Fidelity to the contract: does the first viewport keep the FIRST VIEWPORT promise? Memory test.
- TYPE: display lettering character, compression, weight against the intended world.
- MATERIAL: faked physicality (CSS bevels, embossing, stamped metal or chalk effects imitating a material the page never renders) counts as contradicted: "imitation material is the single most reliable mark of machine made design".
- GROUND: the page field's value and temperature; hunt drift toward the rendition prior (warm cream on light grounds, blue black slate on dark).
- Ceiling: name the world's native devices the build left unused (frame, depth, lettering, ornament density, motion).
- Truth: demonstration data labelled synthetic; no invented claims.
- Floor: hold the screenshots against the craft floor Refuse list (section 17).
- Dispositions: recapture, rebuild, fix, ship. Ship only when nothing material is open. "A page a design director would send back is fix at best however functional it is."
- Keep line: name the one thing that must not be diluted while fixing.

N/A: asset producer agent (raster plates), documenter agent and DESIGN.md format (optional), manual edit applier (live mode plumbing).

---

## 17. The craft floor (craft-floor.md, verbatim in substance)

Verify on the built result (all in one batched look):
- Contrast: body and placeholder text >= 4.5:1, large text >= 3:1. On coloured surfaces tint secondary text from that hue; never grey.
- Depth: shadows carry an offset and a soft blur. A zero offset coloured halo is decoration.
- Spacing: tight groups, generous separation, more space above a heading than below it.
- Type: body measure 65 to 75ch, display max 6rem, tracking floor -0.04em, balanced headings, obvious scale and weight steps; real copy at every breakpoint, fix overflow.
- Motion: one authored moment, not scattered effects and not one identical entrance on every section. Exponential ease out from an already visible default. Blur, backdrop-filter, clip-path, mask and shadow are in the palette when smooth.
- States: hover, disabled, loading, error, empty; real content, working controls, responsive composition, keyboard focus.
- Browser surfaces: selection, caret, scrollbars, focus rings, underline offset, tabular numerals, themed from the palette.
- Copy: the product's own language; controls name their action.
- Coverage: every brief requirement present and findable within seconds. For us: ranking idea, 72,670, the 75 attacked, fan chart, rate bars, results, top 500 table, FAQ.

Refuse (category defaults; the brief may earn some back, except those marked BAN):

Page scaffolds:
- Same size cards of icon plus heading plus text as the page structure. Cards are the lazy container; nested cards are always wrong.
- The hero metric template: big number, small label, supporting stats, accent.
- BAN: a kicker or eyebrow above a heading. "No brief earns it back. The heading carries its own weight." (Guardian style pages love section kickers; do not use them.)
- Section numbers (01 / 02 / 03) unless the sequence itself carries information the reader needs.
- A modal for a task that needs neither interruption nor protected focus.

Surface habits:
- Gradient text; emphasis comes from weight or size.
- Glass and blur as decoration.
- A coloured `border-left` or `border-right` above 1px on cards, list items, callouts or alerts (the "side stripe"; do not style FAQ answers or callouts this way).
- Hard offset shadows (`box-shadow: 4px 4px 0`) outside a truly neobrutalist world.
- Sparklines, progress rings and soft shadowed rounded rectangles standing in for content.
- Monospace as a costume for "technical" rather than for code, data or measurement.
- A system display face (Impact, Arial Black, platform sans) as the display voice.
- Unicode glyphs or emoji standing in for an icon system; icons are drawn, from a real library or authored SVG, one consistent stroke and weight (no padlock emoji, no warning sign glyph).
- Geometric masks standing in for organic contours.
- Light or dark picked by category; pick it from the use scene.

Codex specific extras (good practice for us too):
- Tracking stops at -0.04em; -0.02 to -0.03em usually better.
- Declare elevation once, border OR shadow; a 1px border under a wide soft shadow is the "ghost card". Card radii 12 to 16px; pills only for small controls.
- Real illustration or none: no sketch style SVG scenes, `doodle` classes, `feTurbulence` grain. SVG doing geometry, diagrams and animated linework stays first class.
- Backgrounds are surfaces, textured only from the subject's world: no `repeating-linear-gradient` stripes or two axis grid overlays without a real canvas, map, blueprint or measuring tool under them.
- Claims come from supplied truth; label illustrative values. Naming a concept and then ironising it ("security theater") is not a claim.

"The floor holds the mechanics; it never picks the direction. With every check green, spend the page on the committed world, and when torn between refined and committed, commit."

---

## 18. Full antipattern list: the 62 detector rules

Category "slop" = generated UI tells; "quality" = craft defects. (advisory) = review prompt only; (error) = blocking. Grouped by topic; ids exact.

Colour and surface:
1. `side-tab`: thick coloured border on one side of a card.
2. `border-accent-on-rounded`: thick accent border on a rounded card.
3. `gradient-text`: gradient filled text, especially headings and metrics.
4. `ai-color-palette`: purple or violet gradients, cyan on dark; neon on dark plus a second tell hue.
5. `cream-palette`: warm cream or beige page background by reflex.
6. `dark-glow`: zero offset chromatic halo, or any coloured blurred shadow on a dark ground.
7. `radial-halo`: saturated radial gradient wash as background glow on a dark page.
8. `radial-spotlight-glow`: accent coloured radial "spotlight" cloud behind a hero or section.
9. `gpt-thin-border-wide-shadow` (advisory): every card in a row with hairline border plus wide soft shadow.
10. `repeating-stripes-gradient` (advisory): repeating gradient stripes as decoration.
11. `codex-grid-background` (advisory): decorative hairline grid background tiled at a fixed cell.
12. `hard-offset-shadow` (advisory): unblurred shadow offset 4px or more.
13. `gray-on-color`: grey text on a coloured background.
14. `low-contrast`: under 4.5:1 body, 3:1 large.
15. `buried-raster`: an image under a near opaque wash or at near zero opacity.

Layout and structure:
16. `nested-cards`: cards inside cards.
17. `monotonous-spacing`: one spacing value everywhere.
18. `icon-tile-stack`: rounded square icon tile above a heading (feature card template).
19. `cramped-padding`: text too close to its container edge (min 8px, ideally 12 to 16px).
20. `body-text-viewport-edge`: body text closer than 16px to the viewport edge (12px at 480px or narrower); ideally 24 to 32px.
21. `text-overflow`: content wider than its container, clipped or colliding.
22. `text-occlusion`: text painted under an opaque element or another text run.
23. `first-viewport-column-overflow`: one opening column runs far past the fold while its sibling fits.
24. `edge-flush-cards`: cards flush against a horizontal scroller edge.
25. `clipped-overflow-container` (advisory): overflow hidden clipping a positioned tooltip or popover.
26. `repeated-container-text`: the same literal text 3+ times inside one container.
27. `skipped-heading`: heading levels skip (h1 then h3).
28. `heading-rhythm`: heading closer to the block above than to its own content.

Typography:
29. `overused-font`: Inter, Roboto, Fraunces, Geist, Plus Jakarta Sans, Space Grotesk.
30. `flat-type-hierarchy`: heading and body roles less than 1.25x apart at every step.
31. `italic-serif-display`: oversized italic serif hero headline.
32. `oversized-h1`: a long sentence headline at display size.
33. `extreme-negative-tracking`: crushed letter spacing.
34. `hero-eyebrow-chip`: tiny uppercase tracked label or pill chip right above the hero headline.
35. `kicker-above-heading`: tiny tracked uppercase or small caps label above any heading (banned).
36. `numbered-section-labels` (advisory): small numeric index labels beside section headings.
37. `tight-leading`: line height under 1.3x.
38. `justified-text`: justified narrow column without hyphenation.
39. `straggler` (advisory): one word last line; use `text-wrap: pretty`.
40. `unbalanced-heading` (advisory): last heading line far shorter; use `text-wrap: balance`.
41. `tiny-text`: body under 12px.
42. `undersized-ui-text`: functional text under 11px (10px only for legal smallprint).
43. `all-caps-body`: 80+ characters of uppercase.
44. `wide-tracking`: over 0.05em on body text.
45. `line-length`: lines over about 80 characters; cap at 65 to 75ch.

Motion:
46. `bounce-easing` (advisory): bounce or elastic easing.
47. `pulsing-dot`: decorative pulsing "live" dot.
48. `blinking-cursor` (advisory): fake typing caret in a hero.
49. `marquee`: auto scrolling ticker content.
50. `content-hidden-at-rest` (error): much page text still at opacity 0 or hidden after reveals ran.
51. `script-error` (error): uncaught script error on load.

Illustration and imagery:
52. `shape-assembled-illustration` (advisory): hero sized inline SVG scene built from primitive shapes.
53. `organic-clip-path`: many vertex or curved clip-path faking a torn edge, blob or silhouette.
54. `broken-image`: img with empty, missing or placeholder src.

Copy:
55. `em-dash-overuse` (advisory): 8+ em dashes at about one per 500 characters.
56. `marketing-buzzword`: streamline, empower, supercharge, world class, enterprise grade, next generation, cutting edge, and similar.
57. `aphoristic-cadence`: 3+ sections ending in "X. No Y." or "Not a feature. A platform."
58. `theater-slop-phrase` (advisory): "theater" framing ("security theater").

Design system drift (only meaningful with a DESIGN.md; optional for us):
59. `design-system-font`: font not declared in DESIGN.md.
60. `design-system-color` (advisory): colour outside the documented palette.
61. `design-system-radius` (advisory): radius off the documented scale.
62. `design-system-font-size` (advisory): font size off the documented ramp.

Rule ids surfaced only in prose (craft floor and hooks), worth adding to our own list: glyph or emoji icons; system display face; hero metric template; identical icon card grids; glassmorphism by default; modal by reflex; mono as technical costume; theme picked by category; geometric occlusion masks; sketchy SVG; ghost card (1px border plus wide shadow); over rounding (pills on big cards); section fade on every section.

Running the detector (optional, needs Node via npx; may be blocked by our network limits): `npx impeccable detect index.html`, or against a served page `npx impeccable detect http://localhost:8000` for rendered rules (contrast, tiny text). Exit 2 = findings. Ignore per file with `<!-- impeccable-disable rule-id: reason -->` or per element with `data-impeccable-ignore="rule-id"`.

---

## 19. Not applicable to us (one line each)

- Native iOS and Android guidance (ios.md, android.md, adapt.native.md, audit.native.md): web only page.
- Live mode, generate, live setup, manual edit applier: interactive variant tooling for dev servers.
- Comp led build path, visualize.md comps, region maps, plates, hero gate, component review: image generation workflow; we build in code.
- concept-seed dice roll and decision page: tooling; we keep the thinking (section 1).
- init, document, extract, doctor, hooks: project context files (PRODUCT.md, DESIGN.md, config) and maintenance; optional, not needed for a one page entry.
- Onboarding (onboard.md): no accounts or first run flow. One transferable idea: "show, don't tell" and get to the aha moment fast (the ranking working in the first viewport).
- Shape (shape.md) discovery interview: already done by the team brief; its brief template (job and audience, outcome and proof, direction, scope, states, interaction, constraints) is a fine checklist.
- Operate mode component states for forms, skeleton loaders, overlays escaping containers: mostly n/a; applies only to the table sort, any search box and tooltips.
- Email and print adaptation: n/a (a print stylesheet is optional).
- Telemetry, installation, CLI flags, pinning, git ignore lists: tooling.
