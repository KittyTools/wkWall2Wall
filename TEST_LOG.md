# wkWall2Wall Test Log

## 2026-06-22 - Renderer and Collision Candidate

DLL SHA256:

```text
3049E95853D721CA5D8A34263AC8DDAFA719D35A3531EA36E9492754481F9C23
```

Validated areas:

- Direct3D 9 overlay and wall touch behavior
- OpenGL overlay and wall touch behavior
- DirectDraw overlay and wall touch behavior
- Direct3D 7 overlay and wall touch behavior
- manual worm placement
- automatic worm placement
- centered camera
- free camera
- map cache loading when W:A reuses the last played map
- maps without matching wall metadata staying passive
- wall reset on W:A turn-end messages
- rope, walking, jump, and low-speed rope drop contacts

Notes:

- Overall behavior is stable enough for the next gameplay pass.
- Rare missed wall touches may still happen and should be investigated with targeted logs if they become reproducible.
- Online host/client synchronization is not implemented yet.
