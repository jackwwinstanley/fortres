# Before the Breach: design rulebook

This is the one design rulebook for the page. It merges Aba's three main inspirations with a small Carbon layer. Full digests sit in `inspirations/`:

| Source | File | What it gives us |
|---|---|---|
| taste-skill (Leon Lin) | `inspirations/taste-skill.md` | Page plan in screens, section box, hero entrance, motion budgets, ready-made "moments", copy rules and the AI tells list |
| impeccable (Paul Bakaus) | `inspirations/impeccable.md` | Choosing a visual world, the four "AI looks" to avoid, type and colour floors, data viz rules, critique and audit checklists, 62 anti-patterns |
| Emil Kowalski design engineering | `inspirations/emil-design-eng.md` | When and how to animate: easing by purpose, durations, press feedback, interruptible transitions, stagger, reduced motion |
| IBM Carbon (accent only) | `inspirations/carbon.md` | Gray 100 tokens, IBM Plex Mono, productive motion, tags, the success notification, the focus ring, data viz palette |
| Landing page rules (Aba's first file) | `inspirations/landing-page-design.md` | Type scale and spacing scale, named text styles, ship checklist. Where it conflicts with the three main sources, the main sources win (see "Conflicts settled"). |

Credit line for the page and the pitch: *"Design follows three open design-engineering playbooks (taste-skill, impeccable, Emil Kowalski's design engineering) with IBM Carbon for every system element."*

---

## 1. The direction (write before any code)

- **Thesis.** The few holes that get attacked usually give no warning. The page shows that at once, as threads, and never as a wall of stat tiles.
- **The rut we refuse.** A "cyber" page: near black, neon green or cyan, glowing edges, terminal mono, padlocks, hex rain. Its predictable opposite is refused too: cream newspaper, hairlines, italic serif. We borrow the Guardian's *chart grammar* (thread fan, annotation, honest numbers), not its costume.
- **Story.** In order, a judge 1) understands what CISA's list is, 2) sees that 44 of 75 gave no warning, 3) sees why some holes get attacked, 4) sees how we rank all 72,670, 5) believes the honest result (21 vs 19, could be luck), 6) knows where to find the 500.
- **First screen.** The headline plus the fan of 75 threads already drawn. One hard fact appears in a sentence. The primary action is "See our top 500".
- **Memory test.** An hour later, a judge should say: "the threads that split, and most of them had no warning".

### Aba's story arc (Nov 8, ~4 UTC; this overrides the page plan where they differ)

- **Words → numbers → pictures.** Open in simple everyday terms a non-technical judge understands. Then slowly shift the language into numbers. Then into visuals that are very easy to read. Each section is one step further along that path; never jump straight to a chart.
- **Judges probably know the IBM track**, so the opening can assume "software has security holes; IBM asked us to pick which to fix first". Keep it on topic; don't explain what software or hacking is.
- **It must not feel AI-made.** Most other teams will ship AI-looking pages. Avoid every "AI tell" in taste-skill §13 and impeccable §1.3 and §18. Write copy like a person talking, use real data everywhere, and give the visuals an authored, specific look.
### Organizer's pitch advice (relayed by Aba, Nov 8 ~4:10 UTC)

An organizer asked Aba to "explain it like I'm five" and stressed these points:
- **Say why we rank at all.** Companies have far more holes than people or money to fix them.
- **Show the impact.** Say what a hole can actually lead to when it's used (stolen data, systems taken over, money lost).
- **Hook judges with money or something personal.** Ranking means less money spent fixing holes that never get used, and the holes that would have been costly get fixed first. Or make it personal: "your mom's data" being stolen.
- **Say why regular people should care.** Their own data lives in these companies' systems.
How this shapes the page: the opening "plain words" stage leads with the personal and money stakes, then the why (too many holes, not enough people), and only then moves into numbers. Any money figure must come from a real cited source (for example a published breach cost study) or be labelled as an example; never invent one. Wording rules in §8 still apply.

- When Aba says "ready to build", start from this rulebook. Don't ask Aba to re-explain any of it.

---

## 2. Conflicts settled

| Topic | Sources disagree | Decision |
|---|---|---|
| Gradient text on hero heading | Landing file wants it; impeccable bans gradient text | **No gradient text.** Plain ink. |
| Small uppercase labels above headings ("eyebrows") | Used in our template; impeccable bans them outright; taste bans numbered ones | **None.** The heading carries the section. |
| Glass nav with blur | Landing file wants it; taste and impeccable ban `backdrop-filter` chrome | **Solid nav**, one step off the ground, 1px border. |
| Every section fades up on scroll | Landing file wants it; taste says scroll moves nothing outside its own story section; impeccable says no identical entrance on every section | **No section fade-ins.** Motion only in the hero entrance and the story moments. |
| FAQ as accordion | Template had one; taste says answers open, under 50 words | **Answers open**, no accordion. |
| Font weights | Landing file uses semibold; taste says 400 and 500 only | **400 and 500.** 600 only inside Carbon components, which is Carbon's own weight. |
| Font family | Landing file says Geist; impeccable lists Geist and IBM Plex as reflex faces needing a reason | **Plex Mono gets a stated reason**: it is the Carbon layer, used only for numbers, CVE ids and IBM system elements. The prose face is Aba's call (see section 11). |
| Accent colour | Our sample used lilac; taste says never violet, one accent under 3% of a screen | **Drop lilac.** Mint means "caught", coral means "no warning". Everything else is neutral. |
| Dark or light | Aba liked dark; impeccable says decide from the room, and projectors wash out dark greys and thin strokes | **Decide after a projector test** (section 11). Build both themes from tokens. |
| Hyphens | taste turns on `hyphens: auto` | **Off.** No hyphens in copy (Aba's rule); rewrite instead. CVE ids keep theirs. |

---

## 3. Page plan (one section per screen)

Every section is one or two screens tall at 1440×900 (taste). Text goes on the left and the visual on the right, and never mirrored. Content shares two start lines: the left edge and one split line. A section that is more than 35% empty fails.

| # | Section | Height | Motion beat |
|---|---|---|---|
| 1 | **Hero.** Headline, one sentence with the 72,670 fact, "See our top 500", and the fan at rest (75 threads, neutral) | 1 screen | Hero entrance once on load |
| 2 | **The 44 nobody saw.** The fan chart steps: 75 → warning sign vs none → usual rule 19/0 → our model 19/2 | 2 screens, pinned | **Moment 1: pinned chapters** (the focal sequence) |
| 3 | **Why some get attacked.** Rate bars: N in 1,000 per kind of hole, with k of n | 1 screen | Calm (bars at rest, no animation) |
| 4 | **The thesis line.** One sentence of 12 to 40 words | 1 screen | **Moment 2: word highlight** |
| 5 | **How it works.** Read, rank, check. The Carbon "Granite Guardian check passed" notification sits in step 3 | 1 screen | Calm; the notification slides in once |
| 6 | **Honest results.** 21 vs 19 as two numbers in a sentence, the range bar, and methods compared | 1 screen | **The one count**: 21 and 19 roll once |
| 7 | **Three discoveries.** 59% gave no warning; the July EPSS jump; the leakage test 21 → 28 | 1 screen | Calm |
| 8 | **Our top 500.** Table with Carbon tags for the kind of flaw, plus one Granite reason | 1 to 2 screens | Calm |
| 9 | **Questions.** 5 to 8, answers open | 1 screen | Calm |
| 10 | **Close.** One line plus the same "See our top 500" | 1 screen | Calm |

Budgets (taste, tech column): 2 moments, 1 count, 0 or 1 effect, at most 3 beats, never two beats in neighbouring sections, and the back third of the page calm before the close. Nothing loops past 5 s without a pause control.

---

## 4. Layout and spacing

- Wrap: 1280px wide, 80px gutters on desktop, 12 columns, 24px gap (taste). The phone gutter is at least 16px with safe-area `max()` padding.
- Section box: top padding 120, bottom 72; the h2 comes first and is top aligned (taste).
- Spacing values come only from the scale: 2, 4, 8, 12, 16, 24, 32, 40, 48, 64, 80, 96 (landing file; it matches Carbon's 2 to 96 steps, which is a talking point).
- Leave more space above a heading than below it, and keep one spacing rhythm throughout (impeccable).
- Cards are barely there: one step off the ground, a 1px border at 8 to 14% ink, padding 32 (24 on phone), and no shadow at rest (taste). Never nest cards or put a coloured side stripe on one (impeccable).
- Radius family is "sharp": 4/6/8 (taste, and it suits Carbon's square corners). Nested radius = outer − gap, and only when the result is above 2.
- Check at 390, 768, 1024, 1440 and the projector's real resolution. No sideways page scroll down to 320.

## 5. Type

- One prose family plus IBM Plex Mono for data. At most four font files, `display=swap`.
- Sizes at 1440 / 390 (taste, snapped to the landing scale): h1 72/36, h2 48/30, h3 30/24, lead 20/18, body 16 with line height 26, labels 14 (nothing under 13), stat 36.
- Weights 400 and 500; big type is carried by size and tight tracking (−0.02 to −0.035em, never tighter than −0.04em), never by bold.
- Body text: at least 16px, at most 62 characters a line, 7:1 contrast for reading text and 4.5:1 for muted labels.
- `text-wrap: balance` on headings, `pretty` on body, sentence case everywhere, no italics except quotes, tabular numerals in every number column.
- Mono only for numbers, CVE ids, the table and Carbon elements. Never mono headings (that's a "technical costume").

## 6. Colour

- The page stays 90 to 95% neutral. Colour means something or it isn't there.
- Semantic data colours: **mint = caught**, **coral = no warning sign / missed**, neutral grey threads for everything else. Colour is never the only code: caught threads are also heavier and labelled, and missed ones are fainter.
- Never violet as an accent, never pure `#000`, no glow shadows, no neon (taste, impeccable).
- Dark ground candidates: Carbon Gray 100 `#161616` with layers `#262626` / `#393939` (this matches Carbon exactly, so it's a talking point), or the landing file's `#181818`. Light ground: Carbon Gray 10 / white. Define every colour as a token and check both themes at 4.5:1.
- Carbon's dark categorical palette (`#8a3ffc, #33b1ff, #007d79, #ff7eb6, …`, strictly in order) is used only on **one secondary chart** (the methods comparison), which is where it reads as IBM.

## 7. Motion

Purpose first (Emil): animate only to explain state, show a relationship, give feedback, or carry the one authored moment. Never animate keyboard actions. Content is visible by default; nothing waits at `opacity: 0` for a script (impeccable error rule).

| Use | Curve | Duration | Source |
|---|---|---|---|
| Button press | scale(0.97) | 100–160 ms | Emil |
| Hover on clickables (only under `@media (hover:hover) and (pointer:fine)`) | `cubic-bezier(.2,.8,.2,1)`, 2px lift on cards, 1px on buttons | 150 ms in, 120 ms out | taste |
| UI controls (theme toggle, chart step buttons, table sort) | Carbon standard productive `cubic-bezier(0.2, 0, 0.38, 0.9)` | 110–150 ms | Carbon (talking point) |
| Carbon notification entering | Carbon entrance expressive `cubic-bezier(0, 0, 0.3, 1)` | 240 ms | Carbon |
| Hero entrance: h1 lines rise from word masks, then the rest fades up 12px | `cubic-bezier(.22,1,.36,1)` | 700 ms per line, 80 ms apart; others 520 ms, 60 ms apart; about 1.1 s in all, no loader | taste |
| Threads moving between chart states (on-screen morph) | `cubic-bezier(0.77, 0, 0.175, 1)` (strong ease-in-out) | 500–800 ms, stagger capped at 300 ms total | Emil + impeccable |
| Exits | faster than entrances | about 60% of the entrance | Emil, impeccable |

- Prefer CSS transitions (interruptible) over keyframes for anything a user can trigger again. Use WAAPI for the thread morph.
- Animate transform and opacity (plus clip-path and stroke-dashoffset for drawing). Rate bars use `scaleX`, never width.
- Never: bounce or elastic, parallax, scroll-jacking libraries, scroll cues, marquees, pulsing dots, typing cursors, `scale(0)` entrances (start at 0.95 with opacity), or `transition: all`.
- Reduced motion keeps meaning: the fan still steps through its states by crossfade, the counts show final values, and the word highlight shows the finished sentence.
- Pinned and scrubbed moments run backwards on scroll up and show a finished state at both ends (taste).

## 8. Charts and data

- Every number comes from `outputs/` or `site/data/story.json`; nothing is invented or rounded into a slogan.
- The fan is SVG (75 paths). Anything over a few thousand marks goes on canvas.
- Annotate on the chart itself (labels at thread ends, CVE ids for the two catches) instead of captions underneath. A chart's axis labels and legend are part of the chart; "Figure 1"-style captions are not allowed (taste).
- Bars start at zero; never interpolate across gaps (Carbon). Show k of n beside every rate, and mark groups under 30 cases as "few cases, treat as a hint".
- Chart hit targets are at least 24×24 (44 on touch). Give every chart a keyboard path and a hidden data table (taste's chart components).
- The top 500 table has 48px rows with 1px rules and tabular numerals. On phone, each row becomes a block; no sideways scroll.
- Honesty wording (team rules): "added to CISA's list", not "attacked"; "associated with", not "causes"; Guardian "passed a groundedness check", never "verified"; "IBM Granite (open models, run locally)"; blind-spot catches credit "our text features (keyword flags plus Granite similarity)", and without any text, none.

## 9. Copy

- Plain words for non-technical judges. Define CISA's list, EPSS and CVE once, inline, in a sentence.
- One hard fact on the first screen. Every heading has a noun. Buttons are a verb plus an object ("See our top 500"). Numbers sit inside sentences. 60 to 80 words per screen.
- No hyphens in copy; rewrite the sentence instead (Aba). No em-dash habit, no "X, not Y" reflex, no "X. No Y." sign-offs.
- Banned words and lines: the full lists are in `taste-skill.md` §13 and `impeccable.md` §8. Examples include "threat landscape", "revolutionize", "supercharge", "seamless", "harness", "unlock", "cutting edge" and "world class".
- FAQ: questions in the judge's words (at most 60 characters), answers under 50 words that start with the answer and admit limits.

## 10. IBM Carbon layer (accent only)

Carbon is used for **system feedback and data**, never for the story's look. Plain CSS versions are in `carbon.md` §6.

1. **Granite Guardian check passed**: a Carbon low-contrast success notification (3px `#42be65` bar, the `checkmark--filled` icon as inline SVG, Plex Sans 14px, square corners) that slides in once in "How it works".
2. **IBM Plex Mono** for every number and CVE id (Carbon `code-02`: 14px with 0.32px tracking in tables; larger stats use Plex Mono at the stat size).
3. **Carbon pill tags** for the kind of flaw in the top 500 table (dark tag tokens).
4. **Carbon focus ring**: 2px inset white (dark) or Blue 60 `#0f62fe` (light) on every control.
5. **Carbon productive motion** on all UI controls (section 7).
6. **Carbon dark categorical palette** on the one methods chart.

Line for judges: *"The story's look is our own, but everything that's system feedback (the Granite Guardian check, the tags, focus states, data type and control motion) is built on IBM Carbon tokens, so it would drop straight into an IBM product."*

## 11. Decisions for Aba

1. **Prose font.** Options that fit every source: *Mona Sans* (has a width axis, so the hero can widen as it loads; taste pairs it with a mono), *Chivo* (a sober grotesk with a matching mono), or *Geist* (from your first file; impeccable calls it overused). Plex Mono stays for data either way.
2. **Dark or light.** Dark matches what you liked. Impeccable warns that projectors wash out dark greys and thin lines, so the safest plan is to test the fan on the actual projector or a TV at the venue, then choose. Both themes get built.
3. **Moments.** The plan uses pinned chapters for the fan and word highlight for the thesis line. A third option, *letters assemble* for "Before the Breach" in the hero, would replace the plain hero entrance.

## 12. Finish checklist (merged)

- [ ] Direction holds: no eyebrows, gradient text, glass, glow, neon, nested cards, side-stripe cards, emoji icons or decorative grid backgrounds (impeccable's 62 rules, `impeccable.md` §18).
- [ ] One section per screen; no section more than 35% empty; equal left and right edges.
- [ ] Hero enters once; at most 2 moments + 1 count; calm back third.
- [ ] Every number traced to a file; team wording rules followed.
- [ ] Contrast: 7:1 body, 4.5:1 labels, 3:1 large text, icons and focus, in both themes.
- [ ] Reduced motion keeps every state; no content hidden at rest; works with scripts blocked (finished states).
- [ ] Hover gated to fine pointers; every hover has a tap and keyboard equivalent; targets of 24px or more.
- [ ] Checked at 390, 768, 1024, 1440 and the projector; no sideways scroll.
- [ ] Browser defaults styled: text selection, focus ring, scrollbars, link underline offset, tabular numerals.
- [ ] Copy lint: no banned words, no hyphens in copy, sentence case, buttons are a verb plus an object.
- [ ] Critique pass: Nielsen's 10 heuristics scored 0 to 4, issues ranked P0 to P3, plus the "projector judge" persona (`impeccable.md` §14).
