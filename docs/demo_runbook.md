# Demo runbook: recording the 2-minute video from the presenter page

The page (`site/demo.html`) plays the demo as a fixed sequence. Everything on screen comes from `site/data/demo.json`, which
`python scripts/export_demo.py` builds from the committed results. It works offline.

## Open it
```bash
cd site && python3 -m http.server 8000
```
Open http://localhost:8000/demo.html in Chrome and go full-screen (View → Enter Full Screen, or Ctrl+Cmd+F).

## Keys
| key | action |
|---|---|
| Space or → | next scene |
| ← | back |
| R | restart (black "Press Space" screen) |
| A | autoplay with the timings in `site/demo.js` (hides the cursor) |
| H | hide the small presenter hint |

## Recording settings
1080p, 30 or 60 fps. Hide the Dock, turn on Do Not Disturb, close other windows and notifications. Press H, then A to start.
Autoplay runs about 1 min 55 s. To change a scene's length, edit the `SCENES` table at the top of `site/demo.js`.

## Narration, scene by scene
| scene | seconds | say |
|---|---|---|
| 1 Hook | 8 | "Seventy-two thousand new security holes in 2026. In our test years, about one in 855 ended up on CISA's known-exploited list." |
| 2 What Fortres is | 12 | "Fortres is a triage system. A model ranks every hole and picks the 500 to fix first, and IBM Granite explains each pick." |
| 3 Ranking replay | 15 | "This is a replay of our real run: every hole scored and ranked. The blue tail is the 500 we would fix first." |
| 4 Lookup | 30 | "Take our top pick. Here is its rank, the signals behind it, and a reason written by IBM Granite. Granite Guardian checked it against the facts, and it passed. When the AI's draft does not hold up, we show a plain template instead. And this one ranks in the middle of the pack: no reason, and not in the 500." |
| 5 Honest result | 20 | "In our 2024 and 2025 test, Fortres caught 27 of 75. The best simple rule caught 19. The range is shown, because this is a small test. We could have claimed 33 by using fields filled in after the fact. We didn't." |
| 6 What we found | 20 | "Three findings. 44 of the 75 gave no warning at all. Data that appears after the fact inflates results. And 182 of our 500 AI reasons were replaced by a plain template, because we would rather show a plain sentence than an unsupported one." |
| 7 Close | 10 | "Fortres ranks, Granite explains, Guardian checks." |

## Wording
Say "ranks", "prioritises", "flags", "in our 2024 and 2025 test". The replay is precomputed, so never say it is computing live.

## Fallback
If the page breaks, record the existing site at fortres.us instead.
