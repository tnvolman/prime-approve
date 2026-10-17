# Glyph palette: colorblind check

**Palette adopted:** Okabe-Ito, with white in place of its black, as of the redesign commit. It replaced the earlier red/orange/yellow/green/teal/blue/purple/white set; run `--old` to see that one. The color ids 0–7 and the bit rule are unchanged.

**Method:**
- Simulation uses the Machado, Oliveira & Fernandes (2009) severity-1.0 matrices for protanopia, deuteranopia and tritanopia, applied in linear sRGB.
- Pairwise distances are CIEDE2000 (ΔE00) in CIELAB with a D65 white point. The ΔE00 code is self-checked against Sharma et al. (2005) test pair 1.
- Contrast is the WCAG 2 ratio against the app background #231F20, sampled from a color-corrected simulator screenshot.
- Reproduce with `python3 tools/colorblind.py` (needs numpy). Add `--old` for the previous palette.

A ΔE00 under about 10 is treated as too easy to confuse for a 32 px glyph on a small screen.

## Palette (`GLYPH_RGB` in `src/proto.rs`)

| id | name | sRGB | contrast on #231F20 |
|---|---|---|---|
| 0 | vermillion | #D55E00 | 4.2:1 |
| 1 | orange | #E69F00 | 7.2:1 |
| 2 | yellow | #F0E442 | 12.3:1 |
| 3 | bluish green | #009E73 | 4.8:1 |
| 4 | sky blue | #56B4E9 | 7.1:1 |
| 5 | blue | #0072B2 | 3.1:1 |
| 6 | reddish purple | #CC79A7 | 5.3:1 |
| 7 | white | #EDEDED | 13.9:1 |

Every color clears WCAG's 3:1 minimum for non-text elements. Blue is the lowest, at 3.1:1.

## Closest pairs (ΔE00), current palette

| view | minimum pair | next closest | pairs under 10 |
|---|---|---|---|
| normal vision | orange/yellow **21.7** | vermillion/orange 22.2, sky blue/blue 22.3 | none |
| protanopia | blue/reddish purple **12.2** | sky blue/reddish purple 14.0, orange/yellow 15.2 | none |
| deuteranopia | orange/yellow **11.6** | vermillion/orange 12.5, sky blue/reddish purple 15.7 | none |
| tritanopia | orange/reddish purple **10.9** | bluish green/sky blue 12.1, bluish green/blue 12.4 | none |

The worst case across all four views is **10.9** (tritanopia, orange/reddish purple).

## Previous palette, for the record

The old palette was red #E5484D, orange #F5A524, yellow #F2D53C, green #30A46C, teal #12A594, blue #3E63DD, purple #8E4EC6 and white #EDEDED. Its minimum distances were:

| view | minimum |
|---|---|
| normal vision | 11.7 |
| protanopia | 4.2 (blue/purple) |
| deuteranopia | 3.5 (blue/purple); orange/yellow 7.0 and red/green 9.7 were also under 10 |
| tritanopia | 2.5 (green/teal) |

For a colorblind user it worked like only 5 or 6 colors.

## Remaining notes

- **Shapes still matter.** The 4 shapes (filled circle, filled square, ring, outlined square) carry half the information, so no reading depends on color alone. A text fallback on the agent's screen ("yellow circle, yellow ring, …") is still a good idea.
- **Blue is the dimmest color.** If blue reads poorly on a real panel, the stroked shapes (ring, outlined square) in blue are where it would show first. Consider thicker strokes.
- **Simulation only.** This hasn't been checked on a real Prime screen. The simulator's screenshots swap red and blue, so they can't be used to judge color. Re-check once a dev unit arrives.
