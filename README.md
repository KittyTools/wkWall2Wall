# wkWall2Wall

wkWall2Wall is an experimental WormKit module for Worms Armageddon Wall-X-Wall games.

The goal is simple: when a worm touches a configured wall during a Wall-X-Wall turn, that wall is highlighted as touched. Untouched walls keep the original map look. At the beginning of the next turn, the touched walls are reset.

This project is open source so the W:A community can test it, fork it, improve it, and adapt it to more renderers, schemes, maps, and hosting setups.

## Status

wkWall2Wall is in active development and should be treated as alpha software.

Current alpha build supports:

- loading wall metadata from `.w2w.ini` files
- drawing touched-wall highlights in-game without marking untouched walls
- renderer overlays for Direct3D 9, DirectDraw, and Direct3D 7, with OpenGL kept as a best-effort fallback
- detecting wall touches from W:A physics/collision hooks
- rope collisions, walking contacts, jump contacts, and low-speed rope drop contacts
- resetting touched walls from W:A turn-end messages
- automatic loading of cached map metadata when W:A reuses the last played map
- keeping offline play usable for local testing
- keeping maps without matching wall metadata passive

Known limitations:

- wall touch detection is much more reliable than early tracking builds, but rare missed touches may still happen
- OpenGL does not currently provide the same smooth highlight path as Direct3D 9 and may be less polished
- online synchronization is not ready for normal public games
- if one player does not have the module in an online match, the current alpha build does not yet provide the final compatibility handshake
- `.BIT` map support in the wall editor is not implemented yet

Validated builds should be tracked in `TEST_LOG.md`.

## Installation

1. Download or build `wkWall2Wall.dll`.
2. Copy these items into your Worms Armageddon folder:
   - `wkWall2Wall.dll`
   - `wkWall2Wall.ini`
3. Create this folder if it does not already exist:

```text
Worms Armageddon\User\Walls
```

4. Put `.w2w.ini` wall metadata files in that `User\Walls` folder.
5. In Worms Armageddon, enable `Load WormKit modules` in Advanced Settings.
6. Start W:A and check `wkWall2Wall.log` in the game folder if something does not work.

The default metadata folder is:

```text
User\Walls
```

It is relative to the Worms Armageddon folder unless you set an absolute path in `wkWall2Wall.ini`.

Worms Armageddon maps should stay in the normal W:A user map location:

```text
Worms Armageddon\User\SavedLevels
```

## Creating Wall Metadata

Wall zones are stored in `.w2w.ini` files. The map image is not modified.

Use the wall editor:

```text
tools/wall-editor/index.html
```

Basic workflow:

1. Open the editor in a browser.
2. Choose a map image from `Worms Armageddon\User\SavedLevels`.
3. Draw rectangles around the Wall-X-Wall target walls.
4. Adjust the rectangles until they match the walls.
5. Export the `.w2w.ini` file.
6. Put the exported file in `Worms Armageddon\User\Walls`.

The editor is static HTML/CSS/JavaScript. No server is required.

## Online Model

The intended online model is host-driven:

1. The host chooses the map.
2. The host has already prepared wall metadata for that map.
3. The host shares the metadata with all compatible wkWall2Wall players.
4. Every player uses the same wall rectangles for that match.

If one player does not have a compatible wkWall2Wall version, the module should stay passive and the game should behave normally.

This online sync flow is the next major piece of work and is not ready for normal public matches yet.

## Building

Worms Armageddon is a 32-bit process, so the module must be built as a 32-bit DLL.

Current local build command:

```powershell
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -RunTests
```

Output:

```text
build/llvm-mingw/wkWall2Wall.dll
```

Toolchains and build outputs are intentionally not committed.

## Repository Policy

Every DLL that is copied to the W:A folder and tested in-game should have:

- a commit
- the DLL SHA256 hash
- renderer and resolution notes
- scheme notes, especially manual or automatic worm placement
- a short result in `TEST_LOG.md`

This rule exists so regressions can be bisected instead of guessed.

## Contributing

Contributions are welcome.

Useful ways to help:

- test different W:A renderers and resolutions
- test manual and automatic worm placement schemes
- improve active worm tracking and turn reset detection
- improve the wall editor
- add custom touch/validation sounds in a way that stays online-compatible
- add documentation for players
- review hook safety and renderer compatibility

Please keep changes small and focused. In-game behavior should be documented in `TEST_LOG.md` when a DLL is built and tested.

## Safety

wkWall2Wall should not modify terrain physics or the map image.

The module should remain passive online unless every player in the match is running a compatible version.

## License

This project is released under the MIT License. See `LICENSE`.
